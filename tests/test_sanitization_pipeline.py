"""Tests for the end-to-end sanitization pipeline, fail-closed handling, and zero-leak logging."""

import logging
from unittest.mock import AsyncMock, MagicMock

import pytest

from privacylens.capture import ElementSnapshot, PageSnapshot
from privacylens.models import Finding, scrub_url
from privacylens.pipeline import SanitizationError, sanitize_page
from privacylens.policy.engine import PolicyEngine
from privacylens.sanitize.text import TextSanitizer, sanitize_plain_text
from privacylens.vault import Vault


def test_vault_safety_and_placeholder_stability() -> None:
    """Test that Vault maintains stable placeholders and never exposes raw secrets."""
    vault = Vault()
    secret_card = "4111222233334444"
    tok1 = vault.put("CARD", secret_card)
    tok2 = vault.put("CARD", secret_card)
    assert tok1 == tok2 == "[REDACTED:CARD_1]"

    # Verify representations do not contain the secret
    assert secret_card not in repr(vault)
    assert secret_card not in str(vault)
    assert secret_card not in str(vault.model_dump())


def test_caplog_zero_leak_during_sanitization(caplog: pytest.LogCaptureFixture) -> None:
    """Prove that no raw sensitive value or canary appears in any log record during sanitization."""
    caplog.set_level(logging.DEBUG)

    raw_canary_secret = "CANARY-SECRET-abc12345"
    raw_email = f"user.{raw_canary_secret}@privacylens.test"

    vault = Vault()
    policy = PolicyEngine()
    sanitizer = TextSanitizer(policy_engine=policy, vault=vault)

    snapshot = PageSnapshot(
        url="http://127.0.0.1:8765/account",
        title="Account Portal",
        elements=[
            ElementSnapshot(
                element_id="user-email-field",
                tag="input",
                input_value=raw_email,
                visible_text=raw_email,
            )
        ],
    )
    finding = Finding(
        type="EMAIL",
        start=0,
        end=len(raw_email),
        confidence=1.0,
        source="pattern",
        rule_id="pattern_email",
        element_id="user-email-field",
    )

    view = sanitizer.sanitize_page_snapshot(snapshot, findings=[finding])
    prompt = view.to_prompt_text()

    # Raw secrets must NOT be in prompt text
    assert raw_email not in prompt
    assert raw_canary_secret not in prompt

    # Raw secrets must NOT appear in any captured log message
    for record in caplog.records:
        msg = record.getMessage()
        assert raw_email not in msg
        assert raw_canary_secret not in msg


def test_policy_default_to_mask() -> None:
    """Ensure unknown entity types default to mask (fail closed)."""
    policy = PolicyEngine()
    action = policy.decide("COMPLETELY_UNKNOWN_CUSTOM_TYPE")
    assert action == "mask"


def test_url_and_attribute_scrubbing() -> None:
    """Test scrubbing of sensitive URL query parameters and element attributes."""
    url = "https://app.example.com/login?auth_token=super_secret_token_123&user=john#section"
    scrubbed = scrub_url(url)
    assert "super_secret_token_123" not in scrubbed
    assert "#section" not in scrubbed
    assert "auth_token=%5BREDACTED%3APARAM%5D" in scrubbed

    vault = Vault()
    policy = PolicyEngine()
    attr_text = "Enter OTP received via SMS (e.g. 748192)"
    clean_attr, _, _, _ = sanitize_plain_text(attr_text, vault, policy, hint="otp")
    assert "748192" not in clean_attr


def test_pipeline_fail_closed_on_detector_error() -> None:
    """Ensure that any unexpected error in the pipeline raises SanitizationError."""
    import asyncio

    mock_page = AsyncMock()
    mock_page.url = "http://127.0.0.1:8765/test"
    mock_page.evaluate.return_value = []
    mock_page.title.return_value = "Test Page"
    mock_page.screenshot.return_value = b""

    # Create a mock detection engine that throws an exception
    bad_engine = MagicMock()
    bad_engine.detect_snapshot.side_effect = RuntimeError("Detector crash")

    async def _run() -> None:
        await sanitize_page(
            page=mock_page,
            detection_engine=bad_engine,
            capture_screenshot=False,
        )

    with pytest.raises(SanitizationError, match="Sanitization failed"):
        asyncio.run(_run())


def test_policy_block_withholds_output() -> None:
    """Test that when a policy block action is triggered, view is marked blocked."""
    vault = Vault()
    policy = PolicyEngine()
    sanitizer = TextSanitizer(policy_engine=policy, vault=vault)

    snapshot = PageSnapshot(
        url="http://127.0.0.1:8765/credentials",
        title="Admin Key Portal",
        elements=[],
    )
    block_finding = Finding(
        type="API_KEY",
        start=0,
        end=20,
        confidence=1.0,
        source="pattern",
        rule_id="pattern_api_key",
        element_id="key-elem",
    )

    view = sanitizer.sanitize_page_snapshot(snapshot, findings=[block_finding])
    assert view.blocked is True
    assert view.image_withheld is True
    assert "PAGE BLOCKED BY POLICY" in view.to_prompt_text()
