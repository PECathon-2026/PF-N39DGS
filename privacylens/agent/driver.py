"""BrowserDriver abstraction isolating browser execution across Playwright and Browser Extensions.

Core Guarantees:
1. Universal Protocol: capture(config, want_screenshot), execute(command), current_origin().
2. PlaywrightDriver wraps local browser with unchanged behaviour.
3. ExtensionDriver bridges to connected browser extensions via command queue:
   - Commands: {id, kind: capture|execute|screenshot, payload}.
   - 20s timeout per command; timeout or disconnect fails closed (stops run).
4. Server-Side Secret Resolution:
   - Origin check re-verified at execute time.
   - Resolved secret values transmitted ONLY over localhost in execute payloads.
   - Never in events, logs, audit, or error messages.
   - Unknown origins raise trust_requested event; remembered per (origin, secret_name).
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlparse

from privacylens.agent.actions import (
    ActionUnion,
    ClickAction,
    FinishAction,
    NavigateAction,
    ScrollAction,
    SelectAction,
    TypeAction,
    WaitAction,
    parse_decision,
)
from privacylens.agent.executor import _SECRET_TOKEN_REGEX, _VAULT_TOKEN_REGEX, ActionExecutor
from privacylens.agent.secrets import SecretStore
from privacylens.capture import ElementSnapshot, PageSnapshot, capture_async
from privacylens.events import EventBus
from privacylens.vault import Vault

logger = logging.getLogger(__name__)

DEFAULT_TRUSTED_ORIGINS_FILE = Path("config/trusted_origins.json")


def _get_origin(url: str) -> str:
    """Extract scheme://host:port origin from a URL string."""
    if not url:
        return ""
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return ""
        return f"{parsed.scheme}://{parsed.netloc}".lower()
    except Exception:
        return ""


def load_trusted_origins(path: Path = DEFAULT_TRUSTED_ORIGINS_FILE) -> set[tuple[str, str]]:
    """Load remembered trusted (origin, secret_name) tuples from JSON file."""
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        trusted = set()
        for item in data.get("trusted", []):
            origin = item.get("origin", "").lower()
            sec_name = item.get("secret_name", "").lower()
            if origin and sec_name and item.get("allow", True):
                trusted.add((origin, sec_name))
        return trusted
    except Exception as exc:
        logger.warning("Failed to load trusted origins from %s: %s", path, exc)
        return set()


def is_origin_trusted(
    origin: str,
    secret_name: str,
    path: Path = DEFAULT_TRUSTED_ORIGINS_FILE,
) -> bool:
    """Check if (origin, secret_name) is explicitly trusted."""
    trusted = load_trusted_origins(path)
    norm_origin = origin.lower().strip()
    norm_sec = secret_name.lower().strip()
    return (norm_origin, norm_sec) in trusted or (norm_origin, "*") in trusted


def record_trusted_origin(
    origin: str,
    secret_name: str,
    allow: bool = True,
    path: Path = DEFAULT_TRUSTED_ORIGINS_FILE,
) -> None:
    """Persist an approved (origin, secret_name) trust pair (names only)."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        data: dict[str, Any] = {"trusted": []}
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                pass

        trusted_list = data.setdefault("trusted", [])
        norm_origin = origin.lower()
        norm_sec = secret_name.lower()

        # Update or append
        existing = next(
            (
                t
                for t in trusted_list
                if t.get("origin", "").lower() == norm_origin
                and t.get("secret_name", "").lower() == norm_sec
            ),
            None,
        )
        if existing:
            existing["allow"] = allow
        else:
            trusted_list.append({"origin": norm_origin, "secret_name": norm_sec, "allow": allow})

        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        logger.info(
            "Persisted trust policy: origin='%s', secret_name='%s', allow=%s",
            norm_origin,
            norm_sec,
            allow,
        )
    except Exception as exc:
        logger.error("Failed to save trusted origin: %s", exc)


@dataclass
class ExecResult:
    """Outcome of a browser command execution."""

    success: bool
    summary: str = ""
    error: str | None = None


class BrowserDriver(Protocol):
    """Protocol for abstracting browser interaction (Playwright and Extension)."""

    async def capture(
        self,
        config: Any = None,
        want_screenshot: bool = True,
    ) -> PageSnapshot:
        """Capture DOM snapshot and optional screenshot."""
        ...

    async def execute(
        self,
        command: dict[str, Any] | ActionUnion,
    ) -> ExecResult:
        """Execute a browser action command."""
        ...

    def current_origin(self) -> str:
        """Return the active page origin."""
        ...


class PlaywrightDriver:
    """BrowserDriver implementation wrapping Playwright Page and ActionExecutor."""

    def __init__(
        self,
        page: Any,
        executor: ActionExecutor | None = None,
        vault: Vault | None = None,
        secret_store: SecretStore | None = None,
    ) -> None:
        self.page = page
        self.vault = vault
        self.secret_store = secret_store
        self.executor = executor or ActionExecutor(vault=vault, secret_store=secret_store)

    def current_origin(self) -> str:
        url = getattr(self.page, "url", "") or ""
        return _get_origin(url)

    async def capture(
        self,
        config: Any = None,
        want_screenshot: bool = True,
    ) -> PageSnapshot:
        url = getattr(self.page, "url", "") or "http://127.0.0.1:8765"
        return await capture_async(
            url=url,
            page=self.page,
            capture_screenshot=want_screenshot,
        )

    async def execute(
        self,
        command: dict[str, Any] | ActionUnion,
    ) -> ExecResult:
        action_obj: ActionUnion
        if isinstance(command, dict):
            # Parse dict into validated ActionUnion
            act_type = command.get("action")
            if act_type == "click":
                action_obj = ClickAction(element_id=command.get("element_id", ""))
            elif act_type == "type":
                action_obj = TypeAction(
                    element_id=command.get("element_id", ""),
                    text=command.get("text"),
                    secret_ref=command.get("secret_ref"),
                    clear_first=command.get("clear_first", True),
                )
            elif act_type == "finish":
                action_obj = FinishAction(
                    status=command.get("status", "success"),
                    summary=command.get("summary", ""),
                )
            elif act_type == "navigate":
                action_obj = NavigateAction(url=command.get("url", ""))
            elif act_type == "scroll":
                action_obj = ScrollAction(
                    direction=command.get("direction", "down"),
                    amount=command.get("amount", 300),
                )
            elif act_type == "select":
                action_obj = SelectAction(
                    element_id=command.get("element_id", ""),
                    value=command.get("value", ""),
                )
            elif act_type == "wait":
                action_obj = WaitAction(seconds=float(command.get("seconds", 1.0)))
            else:
                action_obj = parse_decision(json.dumps({"action": command})).action
        else:
            action_obj = command

        ok = await self.executor.execute(action_obj, self.page)
        return ExecResult(
            success=ok,
            summary=f"Executed action {action_obj.action}",
            error=None if ok else "Execution failed on page locator",
        )


class ExtensionDriver:
    """BrowserDriver bridging to a connected browser extension via command queue."""

    def __init__(
        self,
        session_id: str,
        secret_store: SecretStore | None = None,
        vault: Vault | None = None,
        bus: EventBus | None = None,
        trusted_origins_path: Path = DEFAULT_TRUSTED_ORIGINS_FILE,
        allowed_origins: set[str] | None = None,
    ) -> None:
        self.session_id = session_id
        self.secret_store = secret_store
        self.vault = vault
        self.bus = bus
        self.trusted_origins_path = trusted_origins_path
        self.allowed_origins = allowed_origins or {"http://127.0.0.1:8765", "http://localhost:8765"}

        self._pending_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._futures: dict[str, asyncio.Future[dict[str, Any]]] = {}
        self.tab_url: str = ""
        self.connected: bool = True

    def current_origin(self) -> str:
        return _get_origin(self.tab_url)

    async def poll_next_command(self, timeout: float = 20.0) -> dict[str, Any] | None:
        """Called by GET /v1/ext/poll to retrieve pending command."""
        try:
            return await asyncio.wait_for(self._pending_queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    def post_result(self, result_payload: dict[str, Any]) -> bool:
        """Called by POST /v1/ext/result to deliver execution result."""
        cmd_id = result_payload.get("id")
        if not cmd_id or cmd_id not in self._futures:
            logger.warning("Received result for unknown or expired command id: %s", cmd_id)
            return False

        if "url" in result_payload and result_payload["url"]:
            self.tab_url = str(result_payload["url"])

        fut = self._futures.pop(cmd_id)
        if not fut.done():
            fut.set_result(result_payload)
        return True

    def disconnect(self) -> None:
        """Mark extension as disconnected and fail any waiting commands."""
        self.connected = False
        for cid, fut in list(self._futures.items()):
            if not fut.done():
                fut.set_exception(ConnectionError("Extension disconnected (fail-closed)"))
        self._futures.clear()

    async def _dispatch_command(
        self,
        kind: str,
        payload: dict[str, Any],
        timeout: float = 20.0,
    ) -> dict[str, Any]:
        """Enqueue command and await extension response with strict 20s timeout."""
        if not self.connected:
            raise ConnectionError("Extension is disconnected. Aborting run (fail-closed).")

        cmd_id = f"cmd_{uuid.uuid4().hex[:10]}"
        cmd = {
            "id": cmd_id,
            "kind": kind,
            "payload": payload,
        }

        loop = asyncio.get_running_loop()
        future: asyncio.Future[dict[str, Any]] = loop.create_future()
        self._futures[cmd_id] = future
        await self._pending_queue.put(cmd)

        try:
            res = await asyncio.wait_for(future, timeout=timeout)
            return res
        except asyncio.TimeoutError as te:
            self._futures.pop(cmd_id, None)
            self.connected = False  # fail closed on timeout
            logger.error(
                "Extension command '%s' [%s] timed out after %0.1fs",
                kind,
                cmd_id,
                timeout,
            )
            raise TimeoutError(
                f"Extension command {cmd_id} timed out after 20s (fail-closed)"
            ) from te
        except Exception:
            self._futures.pop(cmd_id, None)
            self.connected = False
            raise

    async def capture(
        self,
        config: Any = None,
        want_screenshot: bool = True,
    ) -> PageSnapshot:
        """Request DOM perception & optional visual frame from the extension."""
        res = await self._dispatch_command("capture", {"want_screenshot": want_screenshot})
        data = res.get("data", {})
        self.tab_url = data.get("url", self.tab_url)

        elements_raw = data.get("elements", [])
        elements: list[ElementSnapshot] = []
        for el in elements_raw:
            elements.append(
                ElementSnapshot(
                    element_id=el.get("element_id", ""),
                    tag=el.get("tag", "div"),
                    input_type=el.get("input_type"),
                    name=el.get("name"),
                    autocomplete=el.get("autocomplete"),
                    aria_label=el.get("aria_label"),
                    associated_label_text=el.get("associated_label_text"),
                    placeholder=el.get("placeholder"),
                    visible_text=el.get("visible_text", ""),
                    input_value=el.get("input_value"),
                    href=el.get("href"),
                    bbox=tuple(el.get("bbox", (0.0, 0.0, 0.0, 0.0))),  # type: ignore[arg-type]
                    parent_id=el.get("parent_id"),
                    ancestor_ids=el.get("ancestor_ids", []),
                    is_leaf=el.get("is_leaf", True),
                )
            )

        screenshot_bytes: bytes | None = None
        if want_screenshot and data.get("screenshot_b64"):
            import base64

            screenshot_bytes = base64.b64decode(data["screenshot_b64"])

        return PageSnapshot(
            url=self.tab_url,
            title=data.get("title", ""),
            elements=elements,
            screenshot_bytes=screenshot_bytes,
            page_text=data.get("page_text", ""),
        )

    def _verify_and_resolve_secret(self, secret_ref_or_tok: str) -> str:
        """Verify origin trust and resolve secret on the server."""
        origin = self.current_origin()
        trusted_set = load_trusted_origins(self.trusted_origins_path)
        norm_ref = secret_ref_or_tok.lower().strip()

        is_allowed = (
            origin in self.allowed_origins
            or (origin, norm_ref) in trusted_set
            or (origin, "*") in trusted_set
        )

        if not is_allowed:
            logger.warning(
                "Secret resolution requested on untrusted origin '%s' for '%s'",
                origin,
                norm_ref,
            )
            if self.bus:
                self.bus.emit(
                    "trust_requested",
                    data={"origin": origin, "secret_name": norm_ref},
                )
            raise PermissionError(f"Origin '{origin}' is not trusted for secret '{norm_ref}'")

        if self.secret_store:
            try:
                return self.secret_store.resolve(secret_ref_or_tok)
            except KeyError:
                pass

        if self.vault:
            val = self.vault.resolve(secret_ref_or_tok)
            if val is not None:
                return val

        raise KeyError(f"Secret or token '{secret_ref_or_tok}' could not be resolved on server")

    async def execute(
        self,
        command: dict[str, Any] | ActionUnion,
    ) -> ExecResult:
        """Execute action via extension, resolving synthetic secrets on server first."""
        action_dict: dict[str, Any]
        if isinstance(command, dict):
            action_dict = dict(command)
        else:
            action_dict = command.model_dump()

        act_type = action_dict.get("action")

        # Resolve secrets strictly for TypeAction
        if act_type == "type":
            sec_ref = action_dict.get("secret_ref")
            text_val = action_dict.get("text") or ""

            if sec_ref:
                resolved_val = self._verify_and_resolve_secret(sec_ref)
                action_dict["text"] = resolved_val
                action_dict["secret_ref"] = None

            elif _VAULT_TOKEN_REGEX.search(text_val) or _SECRET_TOKEN_REGEX.search(text_val):
                for m in list(_VAULT_TOKEN_REGEX.finditer(text_val)):
                    tok = m.group(0)
                    raw = self._verify_and_resolve_secret(tok)
                    text_val = text_val.replace(tok, raw)
                for m in list(_SECRET_TOKEN_REGEX.finditer(text_val)):
                    tok = m.group(0)
                    raw = self._verify_and_resolve_secret(tok)
                    text_val = text_val.replace(tok, raw)
                action_dict["text"] = text_val

        # Dispatch execute command to extension
        try:
            res = await self._dispatch_command("execute", action_dict, timeout=20.0)
            return ExecResult(
                success=res.get("success", True),
                summary=res.get("summary", f"Extension executed {act_type}"),
                error=res.get("error"),
            )
        except Exception as exc:
            return ExecResult(
                success=False,
                summary="Execution failed (fail-closed)",
                error=str(exc),
            )
