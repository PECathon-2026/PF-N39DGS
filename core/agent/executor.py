from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from core.agent.validator import Action
from core.vault import vault


@dataclass
class ExecutionResult:
    """Outcome of executing a validated action on the Playwright page."""

    success: bool
    action_type: str
    target: Optional[str] = None
    message: str = ""
    vault_injected: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "action_type": self.action_type,
            "target": self.target,
            "message": self.message,
            "vault_injected": self.vault_injected,
        }


def _find_locator(page: Any, target: str):
    """Locate an element using data-pl-id assigned during perception capture, or id."""
    loc = page.locator(f'[data-pl-id="{target}"]')
    try:
        if loc.count() > 0:
            return loc
    except Exception:
        pass

    loc_id = page.locator(f'#{target}')
    try:
        if loc_id.count() > 0:
            return loc_id
    except Exception:
        pass

    return page.locator(f'[data-pl-id="{target}"]')


def execute_action(page: Any, action: Action) -> ExecutionResult:
    """Execute a validated Action on the current browser page.
    
    Symbolic vault references (e.g. 'vault:CARD_NUMBER') are resolved LOCALLY here
    and injected directly into page inputs. Raw secrets are NEVER logged.
    """
    act_type = action.action_type.lower().strip()
    target = action.target
    vault_injected = False

    try:
        if act_type == "click":
            if not target:
                return ExecutionResult(False, act_type, target, "Click action requires target")
            locator = _find_locator(page, target)
            locator.first.click()
            try:
                page.wait_for_load_state("domcontentloaded", timeout=2000)
            except Exception:
                pass
            return ExecutionResult(True, act_type, target, f"Clicked element {target}")

        elif act_type == "type":
            if not target:
                return ExecutionResult(False, act_type, target, "Type action requires target")

            raw_val = action.value or ""
            if vault.is_vault_ref(raw_val):
                resolved = vault.resolve_value(raw_val)
                vault_injected = True
                safe_log_val = f"<vault secret injected: {raw_val}>"
            else:
                resolved = raw_val
                safe_log_val = f"'{raw_val[:20]}...'" if len(raw_val) > 20 else f"'{raw_val}'"

            locator = _find_locator(page, target)
            locator.first.fill(resolved)
            return ExecutionResult(
                True,
                act_type,
                target,
                f"Typed into {target}: {safe_log_val}",
                vault_injected=vault_injected,
            )

        elif act_type == "select":
            if not target:
                return ExecutionResult(False, act_type, target, "Select action requires target")

            raw_val = action.value or ""
            if vault.is_vault_ref(raw_val):
                resolved = vault.resolve_value(raw_val)
                vault_injected = True
            else:
                resolved = raw_val

            locator = _find_locator(page, target)
            locator.first.select_option(resolved)
            return ExecutionResult(True, act_type, target, f"Selected option on {target}", vault_injected)

        elif act_type == "scroll":
            delta_y = 300
            if action.value and action.value.isdigit():
                delta_y = int(action.value)
            page.mouse.wheel(0, delta_y)
            return ExecutionResult(True, act_type, target, f"Scrolled page by {delta_y}px")

        elif act_type == "wait":
            page.wait_for_timeout(500)
            return ExecutionResult(True, act_type, target, "Waited 500ms")

        elif act_type == "done":
            return ExecutionResult(True, act_type, target, f"Task completed: {action.thought or 'Goal reached'}")

        else:
            return ExecutionResult(False, act_type, target, f"Unknown action type: {act_type}")

    except Exception as e:
        return ExecutionResult(
            False,
            act_type,
            target,
            f"Execution error on {target}: {type(e).__name__}",
            vault_injected=vault_injected,
        )


__all__ = [
    "ExecutionResult",
    "execute_action",
]

