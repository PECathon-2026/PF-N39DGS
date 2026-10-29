"""Human-in-the-loop approval engine for sensitive and high-impact agent actions.

Provides pluggable approval providers (CLI, Scripted, DenyAll, Callback)
for authorization workflows, strictly ensuring raw secrets are never displayed.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from typing import Any

logger = logging.getLogger(__name__)


def format_approval_prompt(action: Any, view_summary: str = "", reason: str = "") -> str:
    """Format safe human-readable approval prompt without raw sensitive values."""
    action_type = getattr(action, "action", getattr(action, "type", str(type(action).__name__)))
    target_elem = getattr(action, "element_id", "N/A")

    details = []
    if hasattr(action, "secret_ref") and action.secret_ref:
        details.append(f"secret_ref='{action.secret_ref}'")
    if hasattr(action, "text") and action.text:
        details.append(f"placeholder='{action.text}'")
    if hasattr(action, "url") and action.url:
        details.append(f"url='{action.url}'")
    if hasattr(action, "amount"):
        details.append(f"amount={action.amount}")

    detail_str = f" ({', '.join(details)})" if details else ""
    lines = [
        "===========================================================",
        "           PRIVACYLENS ACTION APPROVAL REQUIRED            ",
        "===========================================================",
        f"Action Type:  {action_type}",
        f"Target ID:    {target_elem}{detail_str}",
        f"Policy Alert: {reason or 'High-impact action or credential usage'}",
    ]
    if view_summary:
        lines.append(f"Context:      {view_summary}")
    lines.append("===========================================================")
    return "\n".join(lines)


class Approver(ABC):
    """Abstract base class for human-in-the-loop action approval providers."""

    @abstractmethod
    async def request(self, action: Any, view_summary: str = "", reason: str = "") -> bool:
        """Request operator approval for a sensitive or policy-gated action.

        Args:
            action: Proposed action object.
            view_summary: Sanitized summary of active page state.
            reason: Policy rationale why approval was triggered.

        Returns:
            True if authorized, False if rejected or denied.
        """
        pass


class CliApprover(Approver):
    """Terminal interactive approver prompting operator via standard input."""

    def __init__(self, default_allow: bool = False) -> None:
        """Initialize CLI approver."""
        self.default_allow = default_allow

    async def request(self, action: Any, view_summary: str = "", reason: str = "") -> bool:
        """Prompt user in terminal."""
        prompt = format_approval_prompt(action, view_summary, reason)
        print(prompt)
        prompt_char = "[y/N]" if not self.default_allow else "[Y/n]"
        try:
            choice = input(f"Approve action execution {prompt_char}? ").strip().lower()
            if not choice:
                return self.default_allow
            return choice in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            logger.warning("Approval input interrupted or closed, defaulting to denial")
            return False


class ScriptedApprover(Approver):
    """Test-friendly scripted approver with recording capabilities."""

    def __init__(
        self,
        decisions: list[bool] | dict[str, bool] | bool = True,
    ) -> None:
        """Initialize with predefined scripted decisions.

        Args:
            decisions: Boolean list (consumed sequentially), mapping by element ID/action,
                       or static boolean default.
        """
        self.decisions = decisions
        self._index = 0
        self.recorded_requests: list[dict[str, Any]] = []

    async def request(self, action: Any, view_summary: str = "", reason: str = "") -> bool:
        """Record request and return scripted decision."""
        action_type = getattr(action, "action", getattr(action, "type", "action"))
        target = getattr(action, "element_id", "")
        self.recorded_requests.append(
            {
                "action": action,
                "action_type": action_type,
                "element_id": target,
                "view_summary": view_summary,
                "reason": reason,
            }
        )

        if isinstance(self.decisions, bool):
            return self.decisions

        if isinstance(self.decisions, list):
            if self._index < len(self.decisions):
                decision = self.decisions[self._index]
                self._index += 1
                return decision
            return False

        if isinstance(self.decisions, dict):
            if target in self.decisions:
                return self.decisions[target]
            if action_type in self.decisions:
                return self.decisions[action_type]
            return self.decisions.get("default", False)

        return False


class DenyAllApprover(Approver):
    """Fail-closed approver that automatically denies every request."""

    def __init__(self) -> None:
        self.recorded_requests: list[dict[str, Any]] = []

    async def request(self, action: Any, view_summary: str = "", reason: str = "") -> bool:
        """Record and deny."""
        self.recorded_requests.append(
            {
                "action": action,
                "view_summary": view_summary,
                "reason": reason,
            }
        )
        logger.info("DenyAllApprover rejected action: %s", action)
        return False


class CallbackApprover(Approver):
    """Delegates approval decisions to a custom sync or async callable."""

    def __init__(
        self,
        callback: Callable[[Any, str, str], Awaitable[bool] | bool],
    ) -> None:
        self.callback = callback
        self.recorded_requests: list[dict[str, Any]] = []

    async def request(self, action: Any, view_summary: str = "", reason: str = "") -> bool:
        """Invoke callback."""
        self.recorded_requests.append(
            {
                "action": action,
                "view_summary": view_summary,
                "reason": reason,
            }
        )
        res = self.callback(action, view_summary, reason)
        if hasattr(res, "__await__"):
            return await res
        return bool(res)
