from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Union

ALLOWED_ACTIONS: Set[str] = {"click", "type", "select", "scroll", "wait", "done"}
TARGETED_ACTIONS: Set[str] = {"click", "type", "select"}

# Keywords indicating sensitive/irreversible operations requiring explicit approval
APPROVAL_KEYWORDS: Set[str] = {
    "pay",
    "checkout",
    "submit",
    "send",
    "delete",
    "buy",
    "purchase",
    "confirm",
    "order",
    "transfer",
}

# Dangerous JS / code injection patterns
DANGEROUS_PATTERNS = [
    re.compile(r"javascript\s*:", re.I),
    re.compile(r"<\s*script", re.I),
    re.compile(r"\beval\s*\(", re.I),
    re.compile(r"\bdocument\.", re.I),
    re.compile(r"\bwindow\.", re.I),
    re.compile(r"\bFunction\s*\(", re.I),
    re.compile(r"\bexec\s*\(", re.I),
]


@dataclass
class Action:
    """Strongly-typed parsed action proposal. Raw JSON never reaches the executor."""

    action_type: str
    target: Optional[str] = None
    value: Optional[str] = None
    thought: Optional[str] = None
    requires_approval: bool = False
    risk_level: str = "LOW"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_type": self.action_type,
            "target": self.target,
            "value": self.value,
            "thought": self.thought,
            "requires_approval": self.requires_approval,
            "risk_level": self.risk_level,
        }


@dataclass
class ValidationResult:
    """Outcome of validating an action proposal against snapshot and security rules."""

    valid: bool
    action: Optional[Action] = None
    reason: Optional[str] = None
    requires_approval: bool = False


def parse_action_proposal(raw_input: Union[str, Dict[str, Any]]) -> Action:
    """Parse raw LLM JSON proposal into a typed Action dataclass.
    
    Extracts JSON even if wrapped in markdown code blocks.
    """
    if isinstance(raw_input, dict):
        data = raw_input
    elif isinstance(raw_input, str):
        text = raw_input.strip()
        # Handle markdown fenced code blocks: ```json ... ```
        m = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
        if m:
            text = m.group(1).strip()
        else:
            # Look for outermost { ... }
            start = text.find("{")
            end = text.rfind("}")
            if start != -1 and end != -1 and end > start:
                text = text[start : end + 1]

        try:
            data = json.loads(text)
        except Exception as e:
            raise ValueError(f"Failed to parse LLM action as JSON: {type(e).__name__}")
    else:
        raise TypeError(f"Expected str or dict, got {type(raw_input).__name__}")

    if not isinstance(data, dict):
        raise ValueError("Parsed action JSON must be an object")

    action_type = str(data.get("action_type") or data.get("action") or "").lower().strip()
    target = data.get("target")
    if target is not None:
        target = str(target).strip()
    value = data.get("value")
    if value is not None:
        value = str(value)
    thought = data.get("thought")
    if thought is not None:
        thought = str(thought).strip()

    return Action(
        action_type=action_type,
        target=target,
        value=value,
        thought=thought,
    )


def _check_dangerous_patterns(text: Optional[str]) -> bool:
    """Check if a string contains script or injection patterns."""
    if not text:
        return False
    return any(p.search(text) for p in DANGEROUS_PATTERNS)


def validate_action(action: Action, snapshot: Dict[str, Any]) -> ValidationResult:
    """Deterministic validation of proposed action against current page snapshot.
    
    Enforces:
    1. Allowlist: only click, type, select, scroll, wait, done.
    2. Target existence: target must exist in the CURRENT sanitized snapshot.
    3. Injection defense: no arbitrary selectors, script injection, or JS expressions.
    4. Risk tiering: pay, submit, send, delete require human approval.
    """
    # 1. Allowlist check
    act_type = action.action_type.lower().strip()
    if act_type not in ALLOWED_ACTIONS:
        return ValidationResult(
            valid=False,
            action=action,
            reason=f"Disallowed action '{action.action_type}'. Allowed: {sorted(ALLOWED_ACTIONS)}",
        )

    # 2. Injection defense
    if _check_dangerous_patterns(action.target) or _check_dangerous_patterns(action.value):
        return ValidationResult(
            valid=False,
            action=action,
            reason="Injection attempt rejected: payload contains forbidden script or execution pattern",
        )

    # Disallow complex arbitrary CSS selectors or JS paths in target
    if action.target:
        if not re.fullmatch(r"[a-zA-Z0-9_\-]+", action.target):
            return ValidationResult(
                valid=False,
                action=action,
                reason=f"Arbitrary selector rejected: target '{action.target}' is not a valid element identifier",
            )

    # 3. Target existence in CURRENT snapshot
    elements = snapshot.get("elements", [])
    element_map: Dict[str, Dict[str, Any]] = {}
    for el in elements:
        if el.get("el_id"):
            element_map[str(el["el_id"])] = el
        if el.get("id"):
            element_map[str(el["id"])] = el

    if act_type in TARGETED_ACTIONS:
        if not action.target:
            return ValidationResult(
                valid=False,
                action=action,
                reason=f"Target element required for action '{act_type}'",
            )

        if action.target not in element_map:
            return ValidationResult(
                valid=False,
                action=action,
                reason=f"Target '{action.target}' does not exist in current sanitized snapshot",
            )

    # 4. Sensitive action detection (Approval Gate)
    requires_approval = False
    risk_level = "LOW"

    # Check target element attributes in current snapshot
    target_el = element_map.get(action.target) if action.target else None
    if target_el:
        el_context = " ".join([
            str(target_el.get("id", "")),
            str(target_el.get("text", "")),
            str(target_el.get("name", "")),
            str(target_el.get("aria_label", "")),
            str(target_el.get("type", "")),
        ]).lower()

        if any(kw in el_context for kw in APPROVAL_KEYWORDS):
            requires_approval = True
            risk_level = "HIGH"

    # Also check action thought or value for sensitive action intent
    thought_lower = (action.thought or "").lower()
    if any(kw in thought_lower for kw in ("pay", "checkout", "submit order", "delete account")):
        requires_approval = True
        risk_level = "HIGH"

    action.requires_approval = requires_approval
    action.risk_level = risk_level

    return ValidationResult(
        valid=True,
        action=action,
        reason=None,
        requires_approval=requires_approval,
    )


__all__ = [
    "ALLOWED_ACTIONS",
    "APPROVAL_KEYWORDS",
    "Action",
    "ValidationResult",
    "parse_action_proposal",
    "validate_action",
]
