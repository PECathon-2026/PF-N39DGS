"""Tests for privacy-preserving audit logger."""

from pathlib import Path

import pytest

from privacylens.gateway.audit import AuditLogger


def test_audit_logger_records_hashes_and_no_raw_values(tmp_path: Path) -> None:
    """Test that audit log writes hash prefixes and never raw sensitive data."""
    log_file = tmp_path / "logs" / "audit.jsonl"
    audit_logger = AuditLogger(log_path=log_file)

    raw_secret_card = "4111222233334444"
    raw_secret_email = "confidential_ceo@enterprise.com"

    # Compute valid prefixes
    card_hash = AuditLogger.compute_hash_prefix(raw_secret_card)
    email_hash = AuditLogger.compute_hash_prefix(raw_secret_email)

    audit_logger.log_event(
        entity_type="CARD",
        count=1,
        hash_prefixes=[card_hash],
        decision="mask",
    )
    audit_logger.log_event(
        entity_type="EMAIL",
        count=1,
        hash_prefixes=[email_hash],
        decision="mask",
    )

    # Read log content
    assert log_file.exists()
    content = log_file.read_text(encoding="utf-8")

    # Verify log contains hash prefixes and entity metadata
    assert card_hash in content
    assert email_hash in content
    assert '"entity_type": "CARD"' in content
    assert '"decision": "mask"' in content

    # CRITICAL: Verify raw secrets NEVER appear anywhere in the audit log file
    assert raw_secret_card not in content
    assert raw_secret_email not in content
    assert "confidential" not in content
    assert "4111" not in content


def test_audit_logger_rejects_raw_values(tmp_path: Path) -> None:
    """Test that AuditLogger explicitly rejects attempts to log raw sensitive strings."""
    log_file = tmp_path / "audit.jsonl"
    audit_logger = AuditLogger(log_path=log_file)

    raw_card = "4111222233334444"
    raw_email = "test@example.com"

    # Attempting to pass raw card value should raise ValueError
    with pytest.raises(ValueError, match="AuditLogger rejected non-hash value"):
        audit_logger.log_event(
            entity_type="CARD",
            count=1,
            hash_prefixes=[raw_card],
            decision="mask",
        )

    # Attempting to pass raw email should raise ValueError
    with pytest.raises(ValueError, match="AuditLogger rejected non-hash value"):
        audit_logger.log_event(
            entity_type="EMAIL",
            count=1,
            hash_prefixes=[raw_email],
            decision="mask",
        )


def test_audit_logger_rejects_non_hex_strings(tmp_path: Path) -> None:
    """Test rejection of non-hex strings like emails, words, URLs."""
    log_file = tmp_path / "audit.jsonl"
    audit_logger = AuditLogger(log_path=log_file)

    invalid_inputs = [
        "john.doe@example.com",
        "secret_password_123",
        "CANARY-12345678",
        "short",
        "this_is_too_long_to_be_a_hash_prefix_0123456789abcdef",
    ]

    for val in invalid_inputs:
        with pytest.raises(ValueError, match="AuditLogger rejected non-hash value"):
            audit_logger.log_event(
                entity_type="PASSWORD",
                count=1,
                hash_prefixes=[val],
                decision="block",
            )

