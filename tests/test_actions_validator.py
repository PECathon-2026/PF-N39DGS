"""Unit tests for action schemas, decision parser, and ActionValidator."""

import pytest
from pydantic import ValidationError

from privacylens.agent.actions import (
    ActionValidator,
    AgentDecision,
    ClickAction,
    FinishAction,
    NavigateAction,
    ScrollAction,
    TypeAction,
    WaitAction,
    parse_decision,
)
from privacylens.models import SanitizedElement, SanitizedView
from privacylens.vault import Vault


def _sample_view() -> SanitizedView:
    return SanitizedView(
        url="http://127.0.0.1:8765/checkout.html",
        title="Checkout Page",
        elements=[
            SanitizedElement(
                id="btn-order",
                tag="button",
                text="Place Order",
                label="Submit payment and order",
                role="button",
                interactive=True,
            ),
            SanitizedElement(
                id="input-address",
                tag="input",
                text="[REDACTED:ADDRESS_1]",
                label="Delivery Address",
                role="textbox",
                interactive=True,
            ),
            SanitizedElement(
                id="doc-heading",
                tag="h1",
                text="Shopping Cart",
                interactive=False,
            ),
        ],
    )


def test_parse_decision_clean_and_fenced() -> None:
    """Verify parsing clean JSON and markdown fenced JSON."""
    raw_clean = (
        '{"reason": "Click order to proceed", '
        '"action": {"action": "click", "element_id": "btn-order"}}'
    )
    d1 = parse_decision(raw_clean)
    assert d1.reason == "Click order to proceed"
    assert isinstance(d1.action, ClickAction)
    assert d1.action.element_id == "btn-order"

    raw_fenced = f"```json\n{raw_clean}\n```"
    d2 = parse_decision(raw_fenced)
    assert d2.action.element_id == "btn-order"


def test_parse_decision_commentary_recovery() -> None:
    """Verify parsing recovers JSON surrounded by commentary text."""
    raw = (
        "Based on the analysis, I should submit:\n"
        '{"reason": "Submitting order", "action": {"action": "click", "element_id": "btn-order"}}\n'
        "This will finalize checkout."
    )
    decision = parse_decision(raw)
    assert decision.action.element_id == "btn-order"


def test_parse_decision_malformed_fails() -> None:
    """Verify parsing raises ValueError on malformed payload."""
    with pytest.raises(ValueError, match="Failed to parse"):
        parse_decision("Just plain text with no json")


def test_action_models_forbid_extra_fields() -> None:
    """Verify extra fields are strictly forbidden."""
    with pytest.raises(ValidationError):
        ClickAction(element_id="btn", extra_arg="forbidden")  # type: ignore[call-arg]


def test_validator_element_id_lookup() -> None:
    """Verify target element must exist in active SanitizedView."""
    view = _sample_view()
    validator = ActionValidator()

    # Existing element
    valid_dec = AgentDecision(
        reason="Click place order",
        action=ClickAction(element_id="btn-order"),
    )
    res = validator.validate(valid_dec, view)
    assert res.is_valid is True

    # Missing element
    invalid_dec = AgentDecision(
        reason="Click missing",
        action=ClickAction(element_id="non-existent-elem"),
    )
    res_inv = validator.validate(invalid_dec, view)
    assert res_inv.is_valid is False
    assert "not found" in res_inv.error


def test_validator_blocks_canary_and_unmasked_sensitive() -> None:
    """Verify canary and unmasked sensitive entities in action text are rejected."""
    view = _sample_view()
    validator = ActionValidator()

    # Canary in reason
    dec_canary = AgentDecision(
        reason="Targeting CANARY-11223344 for checkout",
        action=ClickAction(element_id="btn-order"),
    )
    res_c = validator.validate(dec_canary, view)
    assert res_c.is_valid is False
    assert "Canary" in res_c.error

    # Luhn valid card number in type text
    dec_card = AgentDecision(
        reason="Entering card",
        action=TypeAction(element_id="input-address", text="4111111111111111"),
    )
    res_card = validator.validate(dec_card, view)
    assert res_card.is_valid is False
    assert "sensitive entity" in res_card.error.lower()


def test_validator_navigation_host_policy() -> None:
    """Verify navigation is restricted to allowlisted hosts."""
    view = _sample_view()
    validator = ActionValidator()

    # Allowed host
    dec_ok = AgentDecision(
        reason="Go to checkout",
        action=NavigateAction(url="http://127.0.0.1:8765/checkout.html"),
    )
    assert validator.validate(dec_ok, view).is_valid is True

    # Non-allowed external host
    dec_bad = AgentDecision(
        reason="Exfiltrate",
        action=NavigateAction(url="https://evil-attacker.com/steal"),
    )
    res = validator.validate(dec_bad, view)
    assert res.is_valid is False
    assert "allowed_hosts" in res.error


def test_validator_bounds_and_approval() -> None:
    """Verify wait/scroll bounds and approval requirement on sensitive controls."""
    view = _sample_view()
    validator = ActionValidator()

    # Wait out of bounds (> 3s)
    dec_wait = AgentDecision(reason="Wait", action=WaitAction(seconds=5.0))
    res_wait = validator.validate(dec_wait, view)
    assert res_wait.is_valid is False
    assert "between 0.1 and 3.0" in res_wait.error

    # Scroll out of bounds (> 1500px)
    dec_scroll = AgentDecision(reason="Scroll", action=ScrollAction(amount=5000))
    res_scroll = validator.validate(dec_scroll, view)
    assert res_scroll.is_valid is False
    assert "between 50 and 1500" in res_scroll.error

    # Place order click requires approval
    dec_order = AgentDecision(
        reason="Submit order",
        action=ClickAction(element_id="btn-order"),
    )
    res_order = validator.validate(dec_order, view)
    assert res_order.is_valid is True
    assert res_order.needs_approval is True
    assert "high-impact" in res_order.approval_reason


def test_validator_vault_placeholder_validation() -> None:
    """Verify referenced placeholders must exist in the active vault."""
    view = _sample_view()
    validator = ActionValidator()
    vault = Vault()
    tok = vault.put("ADDRESS", "123 Elm St")

    # Valid placeholder from vault
    dec_val = AgentDecision(
        reason="Type address",
        action=TypeAction(element_id="input-address", text=tok),
    )
    assert validator.validate(dec_val, view, vault=vault).is_valid is True

    # Unregistered placeholder
    dec_unreg = AgentDecision(
        reason="Type address",
        action=TypeAction(element_id="input-address", text="[REDACTED:ADDRESS_99]"),
    )
    res = validator.validate(dec_unreg, view, vault=vault)
    assert res.is_valid is False
    assert "not registered" in res.error


def test_validator_finish_action() -> None:
    """Verify FinishAction validates cleanly."""
    view = _sample_view()
    validator = ActionValidator()

    dec = AgentDecision(
        reason="Completed successfully",
        action=FinishAction(status="success", summary="Checkout complete"),
    )
    res = validator.validate(dec, view)
    assert res.is_valid is True
    assert res.needs_approval is False
