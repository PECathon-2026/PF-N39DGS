"""Strict action schemas, JSON parsing, and action validation engine for PrivacyLens.

Defines Pydantic action models with extra='forbid' and validates agent proposals
against the active SanitizedView, host allowlists, secret vaults, and security policies.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.parse
from dataclasses import dataclass
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from privacylens.config import AgentConfig, get_config
from privacylens.detect.text_api import detect_text
from privacylens.models import SanitizedView
from privacylens.vault import Vault

logger = logging.getLogger(__name__)

_CANARY_REGEX = re.compile(r"CANARY-[A-Za-z0-9_-]+", re.IGNORECASE)
_VAULT_PLACEHOLDER_REGEX = re.compile(r"\[(?:REDACTED|VAULT):([A-Za-z0-9_]+)\]")
_APPROVAL_KEYWORDS = {
    "pay",
    "place order",
    "submit",
    "purchase",
    "delete",
    "rotate",
    "transfer",
    "sign in",
    "login",
    "password",
    "checkout",
    "order",
}


class ClickAction(BaseModel):
    """Click on an interactive DOM element."""

    model_config = ConfigDict(extra="forbid")
    action: Literal["click"] = "click"
    element_id: str


class TypeAction(BaseModel):
    """Type text or resolve a synthetic secret into an input element."""

    model_config = ConfigDict(extra="forbid")
    action: Literal["type"] = "type"
    element_id: str
    text: str | None = None
    secret_ref: str | None = None
    clear_first: bool = True


class SelectAction(BaseModel):
    """Select an option in a dropdown or combo element."""

    model_config = ConfigDict(extra="forbid")
    action: Literal["select"] = "select"
    element_id: str
    value: str


class ScrollAction(BaseModel):
    """Scroll the page view up or down."""

    model_config = ConfigDict(extra="forbid")
    action: Literal["scroll"] = "scroll"
    direction: Literal["up", "down"] = "down"
    amount: int = 300


class NavigateAction(BaseModel):
    """Navigate browser to an allowlisted URL destination."""

    model_config = ConfigDict(extra="forbid")
    action: Literal["navigate"] = "navigate"
    url: str


class WaitAction(BaseModel):
    """Wait for DOM rendering or animation to complete."""

    model_config = ConfigDict(extra="forbid")
    action: Literal["wait"] = "wait"
    seconds: float = 1.0


class AskUserAction(BaseModel):
    """Request clarification or assistance from the human user."""

    model_config = ConfigDict(extra="forbid")
    action: Literal["ask_user"] = "ask_user"
    question: str


class FinishAction(BaseModel):
    """Signal task completion with final status and summary."""

    model_config = ConfigDict(extra="forbid")
    action: Literal["finish"] = "finish"
    status: Literal["success", "failure"] = "success"
    summary: str


ActionUnion = Annotated[
    ClickAction
    | TypeAction
    | SelectAction
    | ScrollAction
    | NavigateAction
    | WaitAction
    | AskUserAction
    | FinishAction,
    Field(discriminator="action"),
]


class AgentDecision(BaseModel):
    """Validated agent decision wrapping rationale and executable action."""

    model_config = ConfigDict(extra="forbid")
    reason: str
    action: ActionUnion


def _extract_outer_json_block(text: str) -> str:
    """Extract outermost JSON object text enclosed by balanced curly braces."""
    start = text.find("{")
    if start == -1:
        return text.strip()

    depth = 0
    in_string = False
    escape = False

    for idx in range(start, len(text)):
        ch = text[idx]
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if not in_string:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[start : idx + 1]

    return text[start:].strip()


def parse_decision(raw_output: str) -> AgentDecision:
    """Parse raw LLM string into validated AgentDecision with automatic cleanup.

    Args:
        raw_output: Raw text output from LLM completion.

    Returns:
        Validated AgentDecision instance.

    Raises:
        ValueError: If JSON is malformed or schema validation fails.
    """
    clean_text = raw_output.strip()

    # Strip markdown code fences if present
    if "```" in clean_text:
        fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", clean_text)
        if fence_match:
            clean_text = fence_match.group(1).strip()

    try:
        data = json.loads(clean_text)
        return AgentDecision.model_validate(data)
    except Exception:
        # Retry with outer balanced JSON block extractor
        extracted = _extract_outer_json_block(clean_text)
        try:
            data = json.loads(extracted)
            return AgentDecision.model_validate(data)
        except Exception as exc:
            raise ValueError(f"Failed to parse AgentDecision from LLM output: {exc}") from exc


@dataclass
class ValidationResult:
    """Outcome of validating an AgentDecision against active page view and security policy."""

    is_valid: bool
    error: str = ""
    needs_approval: bool = False
    approval_reason: str = ""


class ActionValidator:
    """Validates proposed agent actions against SanitizedView, origin policies, and secrets."""

    def __init__(self, config: AgentConfig | None = None) -> None:
        """Initialize validator with configuration settings."""
        if config is not None:
            self.config = config
        else:
            try:
                self.config = get_config().agent
            except Exception:
                self.config = AgentConfig()

    def validate(
        self,
        decision: AgentDecision,
        view: SanitizedView,
        vault: Vault | None = None,
        secret_store: Any = None,
    ) -> ValidationResult:
        """Validate proposed agent decision against active SanitizedView and safety rules.

        Args:
            decision: Parsed AgentDecision to evaluate.
            view: Active SanitizedView representation of the browser page.
            vault: Active tokenization Vault.
            secret_store: Active synthetic SecretStore.

        Returns:
            ValidationResult with validity status, failure error, and approval flag.
        """
        action = decision.action

        # 1. Inspect reason and text fields for canary or unmasked sensitive data leaks
        texts_to_scan = [decision.reason]
        if isinstance(action, TypeAction) and action.text:
            texts_to_scan.append(action.text)
        elif isinstance(action, AskUserAction):
            texts_to_scan.append(action.question)
        elif isinstance(action, FinishAction):
            texts_to_scan.append(action.summary)

        for txt in texts_to_scan:
            if _CANARY_REGEX.search(txt):
                return ValidationResult(
                    is_valid=False,
                    error="Canary token detected in agent rationale or action text",
                )
            findings = detect_text(txt)
            active_findings = [f for f in findings if f.type != "CARD_MASKED"]
            if active_findings:
                return ValidationResult(
                    is_valid=False,
                    error=(
                        "Unmasked sensitive entity detected in action parameters: "
                        f"{active_findings[0].type}"
                    ),
                )

        # 2. Target element validation
        if isinstance(action, (ClickAction, TypeAction, SelectAction)):
            target_id = action.element_id
            matched_elem = next((el for el in view.elements if el.id == target_id), None)
            if matched_elem is None:
                return ValidationResult(
                    is_valid=False,
                    error=f"Target element '{target_id}' not found in current sanitized view",
                )

        # 3. Destination host validation for navigation
        if isinstance(action, NavigateAction):
            parsed = urllib.parse.urlparse(action.url)
            host = (parsed.hostname or "").lower()
            allowed = {h.lower() for h in self.config.allowed_hosts}
            if host not in allowed:
                return ValidationResult(
                    is_valid=False,
                    error=f"Navigation destination host '{host}' not in allowed_hosts",
                )

        # 4. TypeAction parameters, vault tokens, and secret references
        if isinstance(action, TypeAction):
            if action.text is None and action.secret_ref is None:
                return ValidationResult(
                    is_valid=False,
                    error="TypeAction must specify either 'text' or 'secret_ref'",
                )

            # Validate secret_ref existence
            if action.secret_ref is not None and secret_store is not None:
                if not secret_store.has_secret(action.secret_ref):
                    return ValidationResult(
                        is_valid=False,
                        error=f"Referenced secret '{action.secret_ref}' not found in SecretStore",
                    )

            # Validate vault placeholder existence
            if action.text is not None and vault is not None:
                for match in _VAULT_PLACEHOLDER_REGEX.finditer(action.text):
                    placeholder = match.group(0)
                    if not vault.has_placeholder(placeholder):
                        return ValidationResult(
                            is_valid=False,
                            error=(
                                f"Placeholder '{placeholder}' not registered in active Vault"
                            ),
                        )

        # 5. Bound validation for wait and scroll
        if isinstance(action, WaitAction):
            if action.seconds <= 0.0 or action.seconds > 3.0:
                return ValidationResult(
                    is_valid=False,
                    error=f"Wait duration {action.seconds}s must be between 0.1 and 3.0 seconds",
                )

        if isinstance(action, ScrollAction):
            if action.amount < 50 or action.amount > 1500:
                return ValidationResult(
                    is_valid=False,
                    error=f"Scroll amount {action.amount}px must be between 50 and 1500 pixels",
                )

        # 6. Policy Approval Rules (Human-in-the-Loop)
        needs_approval = False
        approval_reason = ""

        # Check for credential or secret typing
        if isinstance(action, TypeAction) and action.secret_ref:
            needs_approval = True
            approval_reason = f"Injecting stored secret '{action.secret_ref}'"

        # Check for high-impact buttons or interactive controls
        if isinstance(action, (ClickAction, TypeAction, SelectAction)):
            target_id = action.element_id
            matched_elem = next((el for el in view.elements if el.id == target_id), None)
            if matched_elem is not None:
                combined_descriptor = (
                    f"{matched_elem.id} {matched_elem.label or ''} "
                    f"{matched_elem.text or ''} {matched_elem.role or ''}"
                ).lower()
                for kw in _APPROVAL_KEYWORDS:
                    if kw in combined_descriptor:
                        needs_approval = True
                        approval_reason = (
                            f"Action targets high-impact control [{matched_elem.id}]"
                        )
                        break

        return ValidationResult(
            is_valid=True,
            needs_approval=needs_approval,
            approval_reason=approval_reason,
        )
