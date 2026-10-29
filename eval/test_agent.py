from __future__ import annotations

import os
import sys
import pytest
from playwright.sync_api import sync_playwright

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.agent.client import (
    EgressBlockedError,
    build_user_prompt,
    escape_untrusted_content,
    run_agent_loop,
    send_to_model,
)
from core.agent.executor import execute_action
from core.agent.validator import (
    Action,
    ValidationResult,
    parse_action_proposal,
    validate_action,
)
from core.perception.capture import capture
from core.vault import vault


@pytest.fixture
def sample_snapshot():
    return {
        "url": "http://localhost/shop",
        "title": "Shop",
        "text": "Welcome to store",
        "elements": [
            {"el_id": "el_0", "id": "card", "tag": "input", "type": "text", "value": "[REDACTED:CARD]"},
            {"el_id": "el_1", "id": "email", "tag": "input", "type": "text", "value": "[REDACTED:EMAIL]"},
            {"el_id": "el_2", "id": "add-to-cart", "tag": "button", "text": "Add to cart"},
            {"el_id": "el_3", "id": "checkout", "tag": "button", "text": "Checkout / Pay Now"},
        ],
    }


def test_nonexistent_target_rejected(sample_snapshot):
    # Target el_99 does not exist in sample_snapshot
    action = Action(action_type="click", target="el_99")
    v_res = validate_action(action, sample_snapshot)

    assert v_res.valid is False
    assert "does not exist in current sanitized snapshot" in (v_res.reason or "")


def test_disallowed_action_rejected(sample_snapshot):
    # Action 'execute_script' is not in allowlist
    action = Action(action_type="execute_script", target="el_0", value="alert(1)")
    v_res = validate_action(action, sample_snapshot)

    assert v_res.valid is False
    assert "Disallowed action" in (v_res.reason or "")

    # Arbitrary action 'eval'
    action_eval = Action(action_type="eval", target="el_0")
    assert validate_action(action_eval, sample_snapshot).valid is False


def test_injection_attempt_rejected(sample_snapshot):
    # 1. Javascript URI injection in value
    act1 = Action(action_type="type", target="el_0", value="javascript:alert(document.cookie)")
    assert validate_action(act1, sample_snapshot).valid is False
    assert "Injection attempt rejected" in validate_action(act1, sample_snapshot).reason

    # 2. Script tag injection in value
    act2 = Action(action_type="type", target="el_0", value="<script>fetch('http://evil.com')</script>")
    assert validate_action(act2, sample_snapshot).valid is False

    # 3. Arbitrary selector / JS injection in target
    act3 = Action(action_type="click", target="document.cookie")
    res3 = validate_action(act3, sample_snapshot)
    assert res3.valid is False
    assert "rejected" in (res3.reason or "").lower()

    # 4. Arbitrary selector with special characters (e.g. css selector)
    act4 = Action(action_type="click", target="div > button.submit")
    res4 = validate_action(act4, sample_snapshot)
    assert res4.valid is False
    assert "Arbitrary selector rejected" in res4.reason


def test_vault_value_never_in_any_payload(sample_snapshot):
    vault.clear_vault()
    secret_card = "4104332181960018"
    vault.set_secret("CARD_NUMBER", secret_card)

    # 1. Prompt formatting includes only symbolic reference 'vault:CARD_NUMBER', NEVER the raw secret
    prompt = build_user_prompt("Fill in your card and proceed", sample_snapshot)
    assert secret_card not in prompt
    assert "vault:CARD_NUMBER" in prompt

    # 2. send_to_model with safe prompt passes guard
    reply = send_to_model(prompt, task_context="checkout", snapshot_context=sample_snapshot)
    assert isinstance(reply, str)

    # 3. If raw secret value is ever leaked into prompt, send_to_model MUST block via Egress Guard
    leaked_prompt = f"Submit my raw card {secret_card} now"
    with pytest.raises(EgressBlockedError) as exc_info:
        send_to_model(leaked_prompt)
    assert "CARD" in exc_info.value.category_counts or "VAULT" in str(exc_info.value.category_counts)

    vault.clear_vault()


def test_approval_gate_on_sensitive_actions(sample_snapshot):
    # Clicking 'Add to cart' is low risk -> no approval required
    act_cart = Action(action_type="click", target="el_2", thought="Add item to cart")
    v_cart = validate_action(act_cart, sample_snapshot)
    assert v_cart.valid is True
    assert v_cart.requires_approval is False
    assert act_cart.risk_level == "LOW"

    # Clicking 'Checkout / Pay Now' is high risk -> approval REQUIRED
    act_pay = Action(action_type="click", target="el_3", thought="Proceed to pay and checkout")
    v_pay = validate_action(act_pay, sample_snapshot)
    assert v_pay.valid is True
    assert v_pay.requires_approval is True
    assert act_pay.risk_level == "HIGH"


def test_scenario_1_end_to_end_cli_and_approval():
    pages_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pages")
    scen_1_path = os.path.abspath(os.path.join(pages_dir, "scenario_1_ecommerce.html")).replace("\\", "/")
    url = f"file:///{scen_1_path}"

    approval_checked = []

    def mock_approval(action: Action, snap: dict) -> bool:
        approval_checked.append((action.action_type, action.target))
        return True  # approve

    results = run_agent_loop(
        url=url,
        task="Add item to cart and proceed to checkout",
        max_steps=4,
        approval_callback=mock_approval,
    )

    # Must execute steps
    assert len(results) >= 2
    assert any(r.action_type == "click" for r in results)

    # Verified: Human approval gate was paused and triggered on checkout action
    assert len(approval_checked) >= 1
    action_type, target = approval_checked[0]
    assert action_type == "click"
    assert target in ("el_5", "checkout")  # checkout button
