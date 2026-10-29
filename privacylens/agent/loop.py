"""Browser agent execution loop coordinating perception, sanitization, reasoning, and actions.

Implements the core PrivacyLens lifecycle:
1. Perception & Local Sanitization
2. Prompt Construction with Untrusted Delimiters
3. Egress-Gated LLM Completion with Fail-Closed Safety
4. Action Parsing and Validation against Active View
5. Policy-Gated Human Approval
6. Local Browser Action Execution & Re-sanitization
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from privacylens.agent.actions import (
    ActionValidator,
    AgentDecision,
    FinishAction,
    parse_decision,
)
from privacylens.agent.approval import Approver, ScriptedApprover
from privacylens.agent.executor import ActionExecutor
from privacylens.agent.secrets import SecretStore
from privacylens.config import Settings, get_config
from privacylens.events import EventBus
from privacylens.gateway.egress import EgressBlocked
from privacylens.models import SanitizedView
from privacylens.pipeline import sanitize_page
from privacylens.sanitize.injection import (
    defend_view,
    get_injection_system_instructions,
    wrap_untrusted_content,
)
from privacylens.vault import Vault

logger = logging.getLogger(__name__)

RunStatus = Literal[
    "success",
    "failure",
    "blocked",
    "denied",
    "error",
    "max_steps_exceeded",
]


class RunResult(BaseModel):
    """Final outcome summary of an agent execution run."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    status: RunStatus
    steps: int
    actions: list[dict[str, Any]] = Field(default_factory=list)
    llm_calls: int = 0
    duration_seconds: float = 0.0
    summary: str = ""
    error: str | None = None


class ScriptedLLM:
    """Mock LLM returning predefined responses sequentially for deterministic testing."""

    def __init__(self, responses: list[str | AgentDecision | dict[str, Any]]) -> None:
        """Initialize with list of responses."""
        self.responses: list[str] = []
        for r in responses:
            if isinstance(r, str):
                self.responses.append(r)
            elif isinstance(r, AgentDecision):
                self.responses.append(r.model_dump_json())
            elif isinstance(r, dict):
                self.responses.append(json.dumps(r))
        self._index = 0
        self.model = "scripted-mock"

    def complete(self, prompt: str, image: bytes | None = None) -> str:
        """Return next scripted response."""
        if self._index < len(self.responses):
            resp = self.responses[self._index]
            self._index += 1
            return resp
        # Default fallback completion
        return json.dumps(
            {
                "reason": "Default scripted finish",
                "action": {"action": "finish", "status": "failure", "summary": "Out of responses"},
            }
        )


class MockRecordingLLM:
    """Recording LLM capturing all outgoing prompt and image payloads."""

    def __init__(
        self,
        responses: list[str | AgentDecision | dict[str, Any]] | None = None,
    ) -> None:
        """Initialize with optional responses and empty recording log."""
        self.recorded_calls: list[dict[str, Any]] = []
        self._inner = ScriptedLLM(responses or [])
        self.model = "recording-mock"

    def complete(self, prompt: str, image: bytes | None = None) -> str:
        """Record outbound call and delegate response."""
        self.recorded_calls.append(
            {
                "prompt": prompt,
                "has_image": image is not None,
                "image_size": len(image) if image else 0,
            }
        )
        return self._inner.complete(prompt, image)


def _build_agent_prompt(
    task: str,
    view: SanitizedView,
    secrets: SecretStore,
    action_history: list[str],
) -> str:
    """Construct full agent reasoning prompt with security delimiters and instructions."""
    directives = get_injection_system_instructions()

    sec_descs = secrets.get_descriptions()
    if sec_descs:
        sec_lines = [
            f"  - {s.placeholder} ({s.type}): {s.description or s.name}" for s in sec_descs
        ]
        secrets_block = (
            "AVAILABLE USER SECRETS (Reference using placeholders, NEVER invent real secrets):\n"
            + "\n".join(sec_lines)
        )
    else:
        secrets_block = "AVAILABLE USER SECRETS: (None provided)"

    hist_str = "\n".join(f"  {idx + 1}. {act}" for idx, act in enumerate(action_history[-5:]))
    if not hist_str:
        hist_str = "  (No actions executed yet)"

    page_view_str = wrap_untrusted_content(view.to_prompt_text())

    return f"""{directives}

USER TASK:
{task}

{secrets_block}

ACTION HISTORY:
{hist_str}

CURRENT ACTIVE WEBPAGE:
{page_view_str}

ACTION SPECIFICATION:
Return ONLY a valid JSON object (no markdown, no commentary) conforming to this schema:
{{
  "reason": "Brief explanation of your chosen step towards the user goal",
  "action": {{
    "action": "click" | "type" | "select" | "scroll" | "navigate" | "wait" | "ask_user" | "finish",
    ... action-specific parameters ...
  }}
}}

Action parameters reference:
- click: {{"action": "click", "element_id": "target-id"}}
- type: {{"action": "type", "element_id": "target-id", "text": "text", "secret_ref": "card_number"}}
- select: {{"action": "select", "element_id": "target-id", "value": "option_value"}}
- scroll: {{"action": "scroll", "direction": "up" | "down", "amount": 300}}
- navigate: {{"action": "navigate", "url": "http://127.0.0.1:8765/..."}}
- wait: {{"action": "wait", "seconds": 1.0}}
- ask_user: {{"action": "ask_user", "question": "Question for user"}}
- finish: {{"action": "finish", "status": "success" | "failure", "summary": "Detailed summary"}}
"""


async def run_task(
    task: str,
    start_url: str,
    config: Settings | None = None,
    approver: Approver | None = None,
    llm: Any = None,
    secrets: SecretStore | None = None,
    bus: EventBus | None = None,
    page: Any = None,
    max_steps: int | None = None,
) -> RunResult:
    """Execute multi-step browser task under strict sanitization and safety enforcement.

    Args:
        task: Natural language goal for the agent.
        start_url: Initial web URL to navigate to.
        config: Settings instance (defaults to global settings).
        approver: Human approval engine (defaults to ScriptedApprover(True)).
        llm: Language model provider (e.g. GeminiProvider, OllamaProvider, ScriptedLLM).
        secrets: Synthetic user SecretStore.
        bus: Event streaming bus.
        page: Active Playwright Page instance (or None to launch ephemeral).
        max_steps: Maximum reasoning steps before stopping.

    Returns:
        RunResult detailing status, steps taken, actions executed, and duration.
    """
    cfg = config or get_config()
    run_id = f"run_{uuid.uuid4().hex[:8]}"
    event_bus = bus or EventBus(run_id=run_id)
    sec_store = secrets or SecretStore()
    appr = approver or ScriptedApprover(decisions=True)
    validator = ActionValidator(config=cfg.agent)
    limit_steps = max_steps or cfg.agent.max_steps

    start_time = time.time()
    event_bus.emit("run_started", step=0, data={"task": task, "start_url": start_url})

    action_history: list[str] = []
    actions_record: list[dict[str, Any]] = []
    consecutive_rejections = 0
    recent_actions: list[str] = []
    llm_calls = 0

    # Initialize browser page if not passed
    browser_context_owned = False
    browser_instance = None
    playwright_instance = None

    if page is None:
        from playwright.async_api import async_playwright

        playwright_instance = await async_playwright().start()
        channel = cfg.browser.browser_channel
        browser_instance = await playwright_instance.chromium.launch(
            headless=True,
            channel=channel if channel != "chromium" else None,
        )
        context = await browser_instance.new_context()
        page = await context.new_page()
        browser_context_owned = True

    try:
        # Initial navigation to start_url
        logger.info("Agent navigating to start URL: %s", start_url)
        await page.goto(start_url, timeout=15000, wait_until="domcontentloaded")
        executor = ActionExecutor(config=cfg.secrets, vault=None, secret_store=sec_store)

        for step in range(1, limit_steps + 1):
            logger.info("--- Starting agent step %d / %d ---", step, limit_steps)

            # 1. Perception & Local Sanitization
            vault = Vault()
            view = await sanitize_page(page, vault=vault, capture_screenshot=False)
            executor.vault = vault
            if hasattr(llm, "gate") and getattr(llm, "gate", None) is not None:
                llm.gate.register_vault(vault)
            view = defend_view(view, bus=event_bus, step=step)

            event_bus.emit(
                "sanitized",
                step=step,
                data={
                    "url": view.url,
                    "elements_count": len(view.elements),
                    "redactions_count": len(view.redactions),
                },
            )

            if view.blocked:
                event_bus.emit("blocked", step=step, data={"reason": view.block_reason})
                return RunResult(
                    run_id=run_id,
                    status="blocked",
                    steps=step,
                    actions=actions_record,
                    llm_calls=llm_calls,
                    duration_seconds=round(time.time() - start_time, 2),
                    summary=f"Page view blocked by privacy policy: {view.block_reason}",
                )

            # 2. Build Agent Prompt
            prompt = _build_agent_prompt(task, view, sec_store, action_history)

            # 3. Gated LLM Completion
            event_bus.emit(
                "gated",
                step=step,
                data={"model": getattr(llm, "model", "unknown")},
            )

            raw_completion = ""
            for attempt in range(3):
                try:
                    llm_calls += 1
                    raw_completion = llm.complete(
                        prompt=prompt,
                        image=view.image_png if not view.image_withheld else None,
                    )
                    break
                except EgressBlocked as eg_err:
                    # Fail-closed on gate block
                    event_bus.emit(
                        "blocked",
                        step=step,
                        data={"violations": eg_err.violations, "reason": eg_err.reason},
                    )
                    return RunResult(
                        run_id=run_id,
                        status="blocked",
                        steps=step,
                        actions=actions_record,
                        llm_calls=llm_calls,
                        duration_seconds=round(time.time() - start_time, 2),
                        summary="Outbound LLM request blocked by EgressGate",
                        error=str(eg_err),
                    )
                except Exception as exc:
                    err_msg = str(exc)
                    if "429" in err_msg or "quota" in err_msg.lower():
                        backoff = 2.0 * (attempt + 1)
                        logger.warning("LLM rate limit (429) hit, backing off %.1fs...", backoff)
                        await asyncio.sleep(backoff)
                    else:
                        logger.error("LLM completion failed: %s", exc)
                        if attempt == 2:
                            raise

            # 4. Parse Decision (with 1 retry on malformed JSON)
            decision: AgentDecision | None = None
            try:
                decision = parse_decision(raw_completion)
            except Exception as parse_err:
                logger.warning("JSON parse failed: %s. Retrying...", parse_err)
                retry_prompt = (
                    f"{prompt}\n\nATTENTION: Your previous response was invalid JSON. "
                    "You must output ONLY valid raw JSON conforming to the schema."
                )
                try:
                    llm_calls += 1
                    retry_completion = llm.complete(prompt=retry_prompt)
                    decision = parse_decision(retry_completion)
                except Exception as retry_err:
                    consecutive_rejections += 1
                    event_bus.emit(
                        "rejected",
                        step=step,
                        data={"error": f"JSON parse error: {retry_err}"},
                    )
                    if consecutive_rejections >= 3:
                        return RunResult(
                            run_id=run_id,
                            status="failure",
                            steps=step,
                            actions=actions_record,
                            llm_calls=llm_calls,
                            duration_seconds=round(time.time() - start_time, 2),
                            summary="Failed after 3 consecutive invalid JSON responses",
                            error=str(retry_err),
                        )
                    continue

            action_obj = decision.action
            event_bus.emit(
                "proposed",
                step=step,
                data={
                    "action": action_obj.action,
                    "reason": decision.reason,
                    "target": getattr(action_obj, "element_id", None),
                },
            )

            # 5. Validate Action
            val_result = validator.validate(
                decision=decision,
                view=view,
                vault=vault,
                secret_store=sec_store,
            )

            if not val_result.is_valid:
                consecutive_rejections += 1
                logger.warning("Action validation rejected: %s", val_result.error)
                event_bus.emit("rejected", step=step, data={"error": val_result.error})
                if consecutive_rejections >= 3:
                    return RunResult(
                        run_id=run_id,
                        status="failure",
                        steps=step,
                        actions=actions_record,
                        llm_calls=llm_calls,
                        duration_seconds=round(time.time() - start_time, 2),
                        summary=f"Validation failed 3 times: {val_result.error}",
                        error=val_result.error,
                    )
                continue

            consecutive_rejections = 0

            # 6. Policy Approval Check (Human-in-the-Loop)
            if val_result.needs_approval:
                event_bus.emit(
                    "approval_requested",
                    step=step,
                    data={"reason": val_result.approval_reason},
                )
                approved = await appr.request(
                    action=action_obj,
                    view_summary=f"URL: {view.url} - {view.title}",
                    reason=val_result.approval_reason,
                )
                if not approved:
                    event_bus.emit(
                        "denied",
                        step=step,
                        data={"reason": val_result.approval_reason},
                    )
                    return RunResult(
                        run_id=run_id,
                        status="denied",
                        steps=step,
                        actions=actions_record,
                        llm_calls=llm_calls,
                        duration_seconds=round(time.time() - start_time, 2),
                        summary=f"Action denied by human operator: {val_result.approval_reason}",
                    )
                event_bus.emit("approved", step=step)

            # 7. Check Loop Repetition Detection
            action_signature = f"{action_obj.action}:{getattr(action_obj, 'element_id', '')}"
            recent_actions.append(action_signature)
            if len(recent_actions) >= 3 and len(set(recent_actions[-3:])) == 1:
                logger.warning("Repeated action loop: %s repeated 3 times", action_signature)
                return RunResult(
                    run_id=run_id,
                    status="failure",
                    steps=step,
                    actions=actions_record,
                    llm_calls=llm_calls,
                    duration_seconds=round(time.time() - start_time, 2),
                    summary=f"Loop detected: action '{action_signature}' repeated 3 times",
                )

            # 8. Execute Action
            actions_record.append(action_obj.model_dump())
            action_desc = f"{action_obj.action} on [{getattr(action_obj, 'element_id', 'page')}]"
            action_history.append(action_desc)

            if isinstance(action_obj, FinishAction):
                event_bus.emit(
                    "finished",
                    step=step,
                    data={"status": action_obj.status, "summary": action_obj.summary},
                )
                return RunResult(
                    run_id=run_id,
                    status=action_obj.status,
                    steps=step,
                    actions=actions_record,
                    llm_calls=llm_calls,
                    duration_seconds=round(time.time() - start_time, 2),
                    summary=action_obj.summary,
                )

            exec_ok = await executor.execute(action_obj, page, view=view)
            event_bus.emit(
                "executed",
                step=step,
                data={"action": action_obj.action, "success": exec_ok},
            )

            # Allow brief DOM settlement
            await asyncio.sleep(0.3)

        # Max steps exceeded
        event_bus.emit("finished", step=limit_steps, data={"status": "max_steps_exceeded"})
        return RunResult(
            run_id=run_id,
            status="max_steps_exceeded",
            steps=limit_steps,
            actions=actions_record,
            llm_calls=llm_calls,
            duration_seconds=round(time.time() - start_time, 2),
            summary=f"Reached maximum allowed steps ({limit_steps}) without completing",
        )

    finally:
        if browser_context_owned:
            if browser_instance:
                await browser_instance.close()
            if playwright_instance:
                await playwright_instance.stop()
