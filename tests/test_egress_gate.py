"""Unit tests for EgressGate inspection, normalization, and fail-closed security."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from privacylens.config import EgressConfig
from privacylens.gateway.audit import AuditLogger
from privacylens.gateway.egress import Decision, EgressBlocked, EgressGate, EgressRequest
from privacylens.vault import Vault


@pytest.fixture
def test_gate(tmp_path: Path) -> EgressGate:
    """Fixture providing an EgressGate configured with temporary audit log."""
    log_path = tmp_path / "logs" / "audit.jsonl"
    logger = AuditLogger(log_path=log_path)
    config = EgressConfig(
        allowed_hosts=["generativelanguage.googleapis.com", "127.0.0.1", "localhost"],
        on_image_check_failure="block",
    )
    return EgressGate(config=config, audit_logger=logger)


def test_egress_allow_clean_request(test_gate: EgressGate) -> None:
    """Verify that a clean, allowlisted request passes without violations."""
    req = EgressRequest(
        method="POST",
        url="https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent",
        headers={"Content-Type": "application/json", "x-goog-api-key": "fake-api-key-12345"},
        body='{"contents": [{"parts": [{"text": "Which element id is the Place Order button?"}]}]}',
    )
    decision = test_gate.inspect(req)
    assert decision.allowed is True
    assert decision.violations == []
    # Test enforce does not raise
    test_gate.enforce(req)


def test_egress_block_non_allowlisted_host(test_gate: EgressGate) -> None:
    """Verify that non-allowlisted destination hosts are blocked immediately."""
    req = EgressRequest(
        method="POST",
        url="https://unauthorized-external-api.com/v1/chat",
        headers={"Content-Type": "application/json"},
        body='{"text": "Hello world"}',
    )
    decision = test_gate.inspect(req)
    assert decision.allowed is False
    assert any("unauthorized_host" in v for v in decision.violations)
    with pytest.raises(EgressBlocked, match="unauthorized_host"):
        test_gate.enforce(req)


def test_egress_block_canary_token(test_gate: EgressGate) -> None:
    """Verify that any canary token in path, query, header, or body is blocked."""
    # Canary in body
    req_body = EgressRequest(
        method="POST",
        url="http://127.0.0.1:8765/chat",
        body='{"data": "CANARY-73829104 secret marker"}',
    )
    assert test_gate.inspect(req_body).allowed is False
    assert "canary_detected" in test_gate.inspect(req_body).violations

    # Canary in query param
    req_query = EgressRequest(
        method="GET",
        url="http://127.0.0.1:8765/api?token=CANARY-99887766",
    )
    assert test_gate.inspect(req_query).allowed is False
    assert "canary_detected" in test_gate.inspect(req_query).violations


def test_egress_block_sensitive_entities_in_json(test_gate: EgressGate) -> None:
    """Verify that sensitive entities (CARD, EMAIL, etc.) in JSON payloads are caught."""
    # Luhn valid card number
    req_card = EgressRequest(
        method="POST",
        url="http://127.0.0.1:8765/submit",
        body='{"user": {"card_number": "4111111111111111"}}',
    )
    decision = test_gate.inspect(req_card)
    assert decision.allowed is False
    assert any("CARD" in v for v in decision.violations)


def test_egress_block_obfuscated_secrets(test_gate: EgressGate) -> None:
    """Verify that multi-form normalization catches obfuscated secrets."""
    # 1. Zero-width character obfuscation in email
    zw_email = "victim\u200b@secretcorp.com"
    req_zw = EgressRequest(
        method="POST",
        url="http://127.0.0.1:8765/submit",
        body=f'{{"email": "{zw_email}"}}',
    )
    assert test_gate.inspect(req_zw).allowed is False
    assert any("EMAIL" in v for v in test_gate.inspect(req_zw).violations)

    # 2. Spaced card number
    req_spaced = EgressRequest(
        method="POST",
        url="http://127.0.0.1:8765/submit",
        body='{"card": "4111 1111 1111 1111"}',
    )
    assert test_gate.inspect(req_spaced).allowed is False
    assert any("CARD" in v for v in test_gate.inspect(req_spaced).violations)

    # 3. Base64 encoded sensitive text
    b64_val = base64.b64encode(b"contact: admin@targetdomain.org").decode("utf-8")
    req_b64 = EgressRequest(
        method="POST",
        url="http://127.0.0.1:8765/submit",
        body=f'{{"encoded": "{b64_val}"}}',
    )
    assert test_gate.inspect(req_b64).allowed is False
    assert any("EMAIL" in v for v in test_gate.inspect(req_b64).violations)


def test_egress_vault_cross_check(test_gate: EgressGate) -> None:
    """Verify that active vault secrets are caught even if novel or non-standard."""
    vault = Vault()
    secret_pass = "ComplexP@ssw0rd!#987"
    vault.put("PASSWORD", secret_pass)
    test_gate.register_vault(vault)

    # Outgoing payload containing the raw vault password
    req = EgressRequest(
        method="POST",
        url="http://127.0.0.1:8765/login",
        body=f'{{"pwd": "{secret_pass}"}}',
    )
    decision = test_gate.inspect(req)
    assert decision.allowed is False
    assert any("vault_secret:PASSWORD" in v for v in decision.violations)


def test_egress_image_registry(test_gate: EgressGate) -> None:
    """Verify that registered images pass and unregistered images are blocked."""
    # 1x1 dummy PNG bytes
    dummy_png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"

    req_unregistered = EgressRequest(
        method="POST",
        url="http://127.0.0.1:8765/upload",
        body=dummy_png,
    )
    decision_unreg = test_gate.inspect(req_unregistered)
    assert decision_unreg.allowed is False
    assert any("unregistered_image" in v for v in decision_unreg.violations)

    # Register the image
    test_gate.register_sanitized_image(dummy_png)
    decision_reg = test_gate.inspect(req_unregistered)
    assert decision_reg.allowed is True
    assert decision_reg.violations == []


def test_egress_fail_closed_on_corrupted_input(test_gate: EgressGate) -> None:
    """Verify fail-closed error handling when unexpected exception occurs."""
    # Passing an invalid URL that raises an unhandled error inside
    req_bad = EgressRequest(
        method="GET",
        url="http://[invalid-ipv6-bracket/",
    )
    decision = test_gate.inspect(req_bad)
    assert decision.allowed is False
    assert any("internal" in v or "unauthorized" in v for v in decision.violations)
