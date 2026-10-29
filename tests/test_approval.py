"""Unit tests for approval providers and formatting."""

import asyncio

from privacylens.agent.actions import ClickAction, TypeAction
from privacylens.agent.approval import (
    CallbackApprover,
    DenyAllApprover,
    ScriptedApprover,
    format_approval_prompt,
)


def test_format_approval_prompt_safe_metadata() -> None:
    """Verify approval prompt contains element ID and action, never raw values."""
    action = TypeAction(
        element_id="input-card",
        secret_ref="card_number",
        text="[REDACTED:CARD_1]",
    )
    prompt = format_approval_prompt(
        action=action,
        view_summary="Sanitized checkout view",
        reason="Credential injection",
    )

    assert "input-card" in prompt
    assert "type" in prompt
    assert "secret_ref='card_number'" in prompt
    assert "[REDACTED:CARD_1]" in prompt
    assert "Credential injection" in prompt


def test_scripted_approver_list_and_recording() -> None:
    """Verify sequential decision consumption and request auditing."""

    async def _test() -> None:
        approver = ScriptedApprover(decisions=[True, False])
        act1 = ClickAction(element_id="btn-1")
        act2 = ClickAction(element_id="btn-2")
        act3 = ClickAction(element_id="btn-3")

        assert await approver.request(act1, reason="Test 1") is True
        assert await approver.request(act2, reason="Test 2") is False
        # Exhausted list defaults to False
        assert await approver.request(act3, reason="Test 3") is False

        assert len(approver.recorded_requests) == 3
        assert approver.recorded_requests[0]["element_id"] == "btn-1"
        assert approver.recorded_requests[1]["element_id"] == "btn-2"

    asyncio.run(_test())


def test_scripted_approver_dict_mapping() -> None:
    """Verify target element-based approval mapping."""

    async def _test() -> None:
        approver = ScriptedApprover(decisions={"btn-safe": True, "btn-risky": False})

        assert await approver.request(ClickAction(element_id="btn-safe")) is True
        assert await approver.request(ClickAction(element_id="btn-risky")) is False
        assert await approver.request(ClickAction(element_id="btn-other")) is False

    asyncio.run(_test())


def test_deny_all_approver() -> None:
    """Verify DenyAllApprover always refuses requests."""

    async def _test() -> None:
        approver = DenyAllApprover()
        act = ClickAction(element_id="btn-order")
        assert await approver.request(act) is False
        assert len(approver.recorded_requests) == 1

    asyncio.run(_test())


def test_callback_approver_async() -> None:
    """Verify custom async callback integration."""

    async def _test() -> None:
        async def my_callback(action: object, summary: str, reason: str) -> bool:
            return getattr(action, "element_id", "") == "btn-allow"

        approver = CallbackApprover(my_callback)
        assert await approver.request(ClickAction(element_id="btn-allow")) is True
        assert await approver.request(ClickAction(element_id="btn-deny")) is False

    asyncio.run(_test())

