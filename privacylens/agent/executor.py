"""Action execution engine translating high-level actions into Playwright browser calls.

Enforces strict origin-gating on secret and vault placeholder resolution, ensuring
real credentials and PII are injected only on allowlisted origins.
"""

from __future__ import annotations

import logging
import re
import urllib.parse
from typing import Any

from privacylens.agent.actions import (
    ActionUnion,
    AskUserAction,
    ClickAction,
    FinishAction,
    NavigateAction,
    ScrollAction,
    SelectAction,
    TypeAction,
    WaitAction,
)
from privacylens.agent.secrets import SecretStore
from privacylens.config import SecretsConfig, get_config
from privacylens.models import SanitizedView
from privacylens.vault import Vault

logger = logging.getLogger(__name__)

_VAULT_TOKEN_REGEX = re.compile(r"\[(?:REDACTED|VAULT):[A-Za-z0-9_]+\]")
_SECRET_TOKEN_REGEX = re.compile(r"\[SECRET:[A-Za-z0-9_]+\]", re.IGNORECASE)


def _get_page_origin(url: str) -> str:
    """Extract scheme and netloc origin from URL string."""
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}".lower()
    except Exception:
        pass
    return ""


class ActionExecutor:
    """Executes validated agent actions on Playwright browser pages with origin-gated secrets."""

    def __init__(
        self,
        config: SecretsConfig | None = None,
        vault: Vault | None = None,
        secret_store: SecretStore | None = None,
    ) -> None:
        """Initialize ActionExecutor.

        Args:
            config: Secrets configuration specifying allowed origins.
            vault: Active tokenization Vault for surrogate resolution.
            secret_store: Active SecretStore for synthetic user credentials.
        """
        if config is not None:
            self.config = config
        else:
            try:
                self.config = get_config().secrets
            except Exception:
                self.config = SecretsConfig()

        self.vault = vault
        self.secret_store = secret_store
        self.allowed_origins = {o.lower().rstrip("/") for o in self.config.allowed_origins}

    def _verify_origin_for_secret_injection(self, page_url: str) -> None:
        """Verify that current browser page origin is authorized for secret resolution."""
        origin = _get_page_origin(page_url)
        if not origin or origin not in self.allowed_origins:
            logger.error("Blocked secret resolution on unauthorized origin: %s", origin)
            raise PermissionError(
                f"Secret resolution forbidden on unauthorized origin '{origin}'. "
                f"Allowed origins: {self.allowed_origins}"
            )

    def resolve_text_for_typing(self, action: TypeAction, current_url: str) -> str:
        """Resolve placeholders and secret references into real text for typing.

        Args:
            action: TypeAction specifying text or secret_ref.
            current_url: Active URL of the browser page.

        Returns:
            Resolved plaintext string to inject into input control.

        Raises:
            PermissionError: If secret resolution attempted on an unauthorized origin.
            KeyError: If referenced secret or vault token cannot be resolved.
        """
        # If secret_ref is specified, resolve from SecretStore
        if action.secret_ref:
            self._verify_origin_for_secret_injection(current_url)
            if self.secret_store is None:
                raise KeyError(f"No SecretStore available to resolve '{action.secret_ref}'")
            return self.secret_store.resolve(action.secret_ref)

        text = action.text or ""

        # Check if text contains vault placeholders [REDACTED:...]
        vault_matches = list(_VAULT_TOKEN_REGEX.finditer(text))
        secret_matches = list(_SECRET_TOKEN_REGEX.finditer(text))

        if vault_matches or secret_matches:
            self._verify_origin_for_secret_injection(current_url)

            # Resolve vault placeholders
            for match in vault_matches:
                tok = match.group(0)
                if self.vault is None:
                    raise KeyError(f"No Vault available to resolve '{tok}'")
                raw = self.vault.resolve(tok)
                if raw is None:
                    raise KeyError(f"Vault placeholder '{tok}' could not be resolved")
                text = text.replace(tok, raw)

            # Resolve [SECRET:...] tokens in text
            for match in secret_matches:
                tok = match.group(0)
                if self.secret_store is None:
                    raise KeyError(f"No SecretStore available to resolve '{tok}'")
                raw = self.secret_store.resolve(tok)
                text = text.replace(tok, raw)

        return text

    async def execute(
        self,
        action: ActionUnion,
        page: Any,
        view: SanitizedView | None = None,
    ) -> bool:
        """Execute a validated agent action on the browser page.

        Args:
            action: Validated ActionUnion instance.
            page: Playwright Page instance.
            view: Optional current SanitizedView.

        Returns:
            True if action executed successfully, False otherwise.
        """
        logger.info("Executing action: %s", action.action)

        try:
            if isinstance(action, (ClickAction, TypeAction, SelectAction)):
                elem_id = action.element_id
                # Selector matches HTML id or data-pl-id attribute
                selector = f"#{elem_id}, [data-pl-id='{elem_id}']"
                locator = page.locator(selector).first

                if isinstance(action, ClickAction):
                    await locator.click(timeout=8000)
                    return True

                elif isinstance(action, TypeAction):
                    current_url = str(page.url)
                    resolved_text = self.resolve_text_for_typing(action, current_url)
                    if action.clear_first:
                        await locator.fill("", timeout=5000)
                    await locator.fill(resolved_text, timeout=5000)
                    return True

                elif isinstance(action, SelectAction):
                    await locator.select_option(action.value, timeout=5000)
                    return True

            elif isinstance(action, ScrollAction):
                dy = action.amount if action.direction == "down" else -action.amount
                await page.evaluate(f"window.scrollBy(0, {dy})")
                return True

            elif isinstance(action, NavigateAction):
                await page.goto(action.url, timeout=15000, wait_until="domcontentloaded")
                return True

            elif isinstance(action, WaitAction):
                await page.wait_for_timeout(action.seconds * 1000)
                return True

            elif isinstance(action, (AskUserAction, FinishAction)):
                # Informational actions require no browser manipulation
                return True

            return False

        except Exception as exc:
            logger.error("Failed to execute action %s: %s", action.action, exc, exc_info=True)
            return False
