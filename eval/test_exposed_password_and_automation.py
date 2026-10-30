from __future__ import annotations

import json
import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.detect import dom_layer, regex_layer, fusion
from core.sanitize import sanitize_dom, sanitize_text
from core.agent.client import _local_heuristic_planner
from core.agent.validator import Action, validate_action
from core.agent.executor import execute_action
from core.vault import vault


def test_password_masked_in_stars():
    """Verify that a password in an input with type='password' is detected and redacted."""
    snap = {
        "url": "http://localhost/test",
        "elements": [
            {
                "el_id": "el_0",
                "tag": "input",
                "type": "password",
                "name": "pwd",
                "value": "MySecretPass123!",
                "box": {"x": 10, "y": 20, "w": 200, "h": 30},
            }
        ],
        "text": "Please enter your password",
    }
    findings = dom_layer.scan_dom(snap)
    assert any(f.category == "PASSWORD" for f in findings)

    san = sanitize_dom(snap, findings)
    assert san["elements"][0]["value"] == "[REDACTED:PASSWORD]"


def test_password_exposed_plain_text():
    """Verify that when a user toggles 'Show Password' (type='text') or when a password is in plain text,
    it is detected and redacted."""
    # 1. Input field toggled to type='text' with name='password' or placeholder='Password'
    snap_toggled = {
        "url": "http://localhost/login",
        "elements": [
            {
                "el_id": "el_1",
                "tag": "input",
                "type": "text",  # toggled exposed!
                "name": "password",
                "placeholder": "Enter your password",
                "value": "ExposedSecret2026!",
                "box": {"x": 15, "y": 25, "w": 220, "h": 35},
            }
        ],
        "text": "Your temporary password is: ExposedSecret2026!",
    }
    findings = dom_layer.scan_dom(snap_toggled)
    r_findings = regex_layer.scan_text(snap_toggled["text"])
    all_f = fusion.fuse(findings + r_findings)

    assert any(f.category == "PASSWORD" for f in all_f)

    san = sanitize_dom(snap_toggled, all_f)
    assert san["elements"][0]["value"] == "[REDACTED:PASSWORD]"
    assert "ExposedSecret2026!" not in san["text"]
    assert "[REDACTED:PASSWORD]" in san["text"]


def test_password_exposed_in_text_phrases():
    """Verify regex scans catch various exposed password expressions in text."""
    phrases = [
        "Your password: SecretKey99!",
        "temporary password is: TempPass#1",
        "default password is admin_pass",
        "Password: MySpecialSecret",
        "set to password: user_pass_88",
    ]
    for text in phrases:
        findings = regex_layer.scan_text(text)
        assert any(f.category == "PASSWORD" for f in findings), f"Failed to detect password in: {text}"
        sanitized = sanitize_text(text, findings)
        assert "[REDACTED:PASSWORD]" in sanitized


def test_login_automation_heuristic():
    """Verify that when the user gives a 'login' instruction, the agent automates the multi-step sequence."""
    # Step 0: Page has empty username and password fields -> should type username
    snap_step0 = {
        "elements": [
            {"el_id": "el_0", "tag": "input", "type": "email", "name": "email", "value": ""},
            {"el_id": "el_1", "tag": "input", "type": "password", "name": "password", "value": ""},
            {"el_id": "el_2", "tag": "button", "type": "submit", "text": "Sign In"},
        ]
    }
    action0_raw = _local_heuristic_planner("login", snap_step0, step=0)
    act0 = json.loads(action0_raw)
    assert act0["action_type"] == "type"
    assert act0["target"] == "el_0"
    assert "vault:" in act0["value"]

    # Step 1: Username filled, password empty -> should type password
    snap_step1 = {
        "elements": [
            {"el_id": "el_0", "tag": "input", "type": "email", "name": "email", "value": "user@test.org"},
            {"el_id": "el_1", "tag": "input", "type": "password", "name": "password", "value": ""},
            {"el_id": "el_2", "tag": "button", "type": "submit", "text": "Sign In"},
        ]
    }
    action1_raw = _local_heuristic_planner("login", snap_step1, step=1)
    act1 = json.loads(action1_raw)
    assert act1["action_type"] == "type"
    assert act1["target"] == "el_1"
    assert "vault:PASSWORD" in act1["value"]

    # Step 2: Both credentials filled -> should click Sign In button
    snap_step2 = {
        "elements": [
            {"el_id": "el_0", "tag": "input", "type": "email", "name": "email", "value": "user@test.org"},
            {"el_id": "el_1", "tag": "input", "type": "password", "name": "password", "value": "[REDACTED:PASSWORD]"},
            {"el_id": "el_2", "tag": "button", "type": "submit", "text": "Sign In"},
        ]
    }
    action2_raw = _local_heuristic_planner("login", snap_step2, step=2)
    act2 = json.loads(action2_raw)
    assert act2["action_type"] == "click"
    assert act2["target"] == "el_2"


def test_login_automation_various_phrases():
    """Verify that different natural phrasing triggers the login automation flow."""
    snap = {
        "elements": [
            {"el_id": "el_0", "tag": "input", "type": "email", "name": "email", "value": ""},
            {"el_id": "el_1", "tag": "input", "type": "password", "name": "password", "value": ""},
            {"el_id": "el_2", "tag": "button", "type": "submit", "text": "Log In"},
        ]
    }
    phrases = ["log in", "log in to my account", "signin", "sign in", "sign-in", "enter credentials", "authenticate"]
    for phrase in phrases:
        raw = _local_heuristic_planner(phrase, snap, step=0)
        action = json.loads(raw)
        assert action["action_type"] == "type", f"Failed for phrase: '{phrase}'"
        assert action["target"] == "el_0"
        assert "vault:" in action["value"]


def test_navigate_action_validation():
    """Verify that navigate action is allowed and validates URL safely."""
    snap = {"elements": []}
    
    # Valid navigations
    v1 = validate_action(Action(action_type="navigate", value="https://example.com"), snap)
    assert v1.valid is True
    
    v2 = validate_action(Action(action_type="navigate", value="http://localhost:8000/test"), snap)
    assert v2.valid is True

    # Invalid navigation: javascript URI
    v3 = validate_action(Action(action_type="navigate", value="javascript:alert(1)"), snap)
    assert v3.valid is False

    # Invalid navigation: relative or malformed
    v4 = validate_action(Action(action_type="navigate", value="ftp://evil.com"), snap)
    assert v4.valid is False


def test_vault_symbolic_resolution():
    """Verify that both vault:PASSWORD and $VAULT:PASSWORD resolve locally."""
    vault.set_secret("PASSWORD", "SuperSecretPwd123")
    assert vault.resolve_value("vault:PASSWORD") == "SuperSecretPwd123"
    assert vault.resolve_value("$VAULT:PASSWORD") == "SuperSecretPwd123"
    assert vault.resolve_value("vault:password") == "SuperSecretPwd123"
