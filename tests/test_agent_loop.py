"""Unit tests for agent loop perception, reasoning, safety gates, and stop conditions."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

from privacylens.agent.approval import DenyAllApprover, ScriptedApprover
from privacylens.agent.loop import RunResult, ScriptedLLM, run_task
from privacylens.gateway.egress import EgressBlocked
from privacylens.models import SanitizedElement, SanitizedView
from privacylens.vault import Vault


def _make_mock_page() -> MagicMock:
    page = MagicMock()
    page.url = "http://127.0.0.1:8765/checkout.html"
    locator = MagicMock()
    locator.click = AsyncMock()
    locator.fill = AsyncMock()
    locator.select_option = AsyncMock()
    page.locator.return_value.first = locator
    page.goto = AsyncMock()
    page.wait_for_timeout = AsyncMock()
    page.evaluate = AsyncMock()
    return page


def _make_mock_view() -> tuple[SanitizedView, Vault]:
    vault = Vault()
    view = SanitizedView(
        url="http://127.0.0.1:8765/checkout.html",
        title="Checkout Page",
        elements=[
            SanitizedElement(
                id="btn-order",
                tag="button",
                text="Place Order",
                label="Submit order",
                interactive=True,
            ),
            SanitizedElement(
                id="inp-address",
                tag="input",
                text="123 Street",
                interactive=True,
            ),
        ],
    )
    return view, vault


def test_scripted_llm_cycle() -> None:
    """Verify ScriptedLLM iterates through responses."""
    r1 = {"reason": "click button", "action": {"action": "click", "element_id": "btn-order"}}
    r2 = {
        "reason": "finish task",
        "action": {"action": "finish", "status": "success", "summary": "done"},
    }
    llm = ScriptedLLM([r1, r2])

    c1 = llm.complete("prompt 1")
    assert "btn-order" in c1
    c2 = llm.complete("prompt 2")
    assert "finish" in c2


def test_run_task_success_flow(monkeypatch: object) -> None:
    """Verify successful task execution loop."""

    async def _test() -> None:
        mock_page = _make_mock_page()

        # Monkeypatch sanitize_page to return our mock view without browser launch
        import privacylens.agent.loop as loop_mod

        async def _mock_sanitize(p: object, **kw: object) -> SanitizedView:
            return _make_mock_view()[0]

        monkeypatch.setattr(loop_mod, "sanitize_page", _mock_sanitize)  # type: ignore[attr-defined]

        responses = [
            {
                "reason": "Place order",
                "action": {"action": "click", "element_id": "btn-order"},
            },
            {
                "reason": "Finished checkout",
                "action": {
                    "action": "finish",
                    "status": "success",
                    "summary": "Order successfully placed",
                },
            },
        ]
        llm = ScriptedLLM(responses)
        approver = ScriptedApprover(decisions=True)

        res: RunResult = await run_task(
            task="Order item",
            start_url="http://127.0.0.1:8765/checkout.html",
            approver=approver,
            llm=llm,
            page=mock_page,
            max_steps=5,
        )

        assert res.status == "success"
        assert res.steps == 2
        assert "Order successfully placed" in res.summary
        assert len(approver.recorded_requests) == 1

    asyncio.run(_test())


def test_run_task_approval_denial(monkeypatch: object) -> None:
    """Verify human denial terminates execution cleanly with denied status."""

    async def _test() -> None:
        mock_page = _make_mock_page()

        import privacylens.agent.loop as loop_mod

        async def _mock_sanitize(p: object, **kw: object) -> SanitizedView:
            return _make_mock_view()[0]

        monkeypatch.setattr(loop_mod, "sanitize_page", _mock_sanitize)  # type: ignore[attr-defined]

        # Action requires approval
        responses = [
            {
                "reason": "Place order",
                "action": {"action": "click", "element_id": "btn-order"},
            }
        ]
        llm = ScriptedLLM(responses)
        approver = DenyAllApprover()

        res = await run_task(
            task="Order item",
            start_url="http://127.0.0.1:8765/checkout.html",
            approver=approver,
            llm=llm,
            page=mock_page,
            max_steps=5,
        )

        assert res.status == "denied"
        assert "denied by human operator" in res.summary

    asyncio.run(_test())


def test_run_task_egress_gate_block(monkeypatch: object) -> None:
    """Verify egress gate block immediately fails closed without retry."""

    async def _test() -> None:
        mock_page = _make_mock_page()

        import privacylens.agent.loop as loop_mod

        async def _mock_sanitize(p: object, **kw: object) -> SanitizedView:
            return _make_mock_view()[0]

        monkeypatch.setattr(loop_mod, "sanitize_page", _mock_sanitize)  # type: ignore[attr-defined]

        class LeakingLLM:
            model = "test-leaker"

            def complete(self, prompt: str, image: bytes | None = None) -> str:
                raise EgressBlocked("Sensitive PII leak detected", ["sensitive_entity:CARD"])

        res = await run_task(
            task="Test gate block",
            start_url="http://127.0.0.1:8765/checkout.html",
            llm=LeakingLLM(),
            page=mock_page,
            max_steps=5,
        )

        assert res.status == "blocked"
        assert "EgressGate" in res.summary

    asyncio.run(_test())


def test_run_task_loop_detection(monkeypatch: object) -> None:
    """Verify repeated action loop terminates execution."""

    async def _test() -> None:
        mock_page = _make_mock_page()

        import privacylens.agent.loop as loop_mod

        async def _mock_sanitize(p: object, **kw: object) -> SanitizedView:
            return _make_mock_view()[0]

        monkeypatch.setattr(loop_mod, "sanitize_page", _mock_sanitize)  # type: ignore[attr-defined]

        # Repeating same click 3 times
        responses = [
            {
                "reason": "Clicking button",
                "action": {"action": "click", "element_id": "inp-address"},
            }
        ] * 4
        llm = ScriptedLLM(responses)

        res = await run_task(
            task="Loop test",
            start_url="http://127.0.0.1:8765/checkout.html",
            llm=llm,
            page=mock_page,
            max_steps=5,
        )

        assert res.status == "failure"
        assert "Loop detected" in res.summary

    asyncio.run(_test())
