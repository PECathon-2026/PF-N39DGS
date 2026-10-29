"""Unit tests for Vault, PolicyEngine, and TextSanitizer."""

import pickle

import pytest

from privacylens.detect.text_api import detect_text
from privacylens.models import scrub_url
from privacylens.policy.engine import PolicyEngine
from privacylens.sanitize.text import sanitize_plain_text
from privacylens.vault import Vault


def test_vault_placeholder_generation_and_stability() -> None:
    """Test surrogate placeholder generation, stability, and format."""
    vault = Vault()

    card_1 = "4111222233334444"
    card_2 = "5555666677778888"

    tok1 = vault.put("CARD", card_1)
    assert tok1 == "[REDACTED:CARD_1]"

    # Re-inserting identical raw secret reuses placeholder
    tok1_again = vault.put("CARD", card_1)
    assert tok1_again == tok1

    # Inserting different secret increments counter
    tok2 = vault.put("CARD", card_2)
    assert tok2 == "[REDACTED:CARD_2]"

    # Different type gets its own sequence counter
    email_tok = vault.put("EMAIL", "test@example.com")
    assert email_tok == "[REDACTED:EMAIL_1]"


def test_vault_resolution_and_wipe() -> None:
    """Test placeholder resolution and cache wiping."""
    vault = Vault()

    secret = "TopSecretPassword123"
    tok = vault.put("PASSWORD", secret)

    resolved = vault.resolve(tok)
    assert resolved == secret

    # Non-existent placeholder
    assert vault.resolve("[REDACTED:CARD_999]") is None

    # Wipe clears secrets
    vault.wipe()
    assert len(vault) == 0
    assert vault.resolve(tok) is None


def test_vault_security_and_serialization_safety() -> None:
    """Verify that Vault never exposes raw values via repr, str, or pickle."""
    vault = Vault()
    secret = "SUPER_SECRET_TOKEN_XYZ"
    vault.put("API_KEY", secret)

    # Repr / str check
    assert secret not in repr(vault)
    assert secret not in str(vault)

    # Pickle rejection
    with pytest.raises(TypeError, match="serialization is prohibited"):
        pickle.dumps(vault)


def test_policy_engine_normalization_and_fail_closed() -> None:
    """Test policy decision normalization and default fail-closed behavior."""
    policy = PolicyEngine(profile="default")

    # Normalization
    assert policy.decide("PERSON") == "mask"
    assert policy.decide("LOCATION") == "mask"

    # Known policy actions in default profile
    assert policy.decide("CARD") == "mask"
    assert policy.decide("CARD_MASKED") == "allow"
    assert policy.decide("PASSWORD") == "mask"
    assert policy.decide("OTP") == "mask"
    assert policy.decide("API_KEY") == "mask"
    assert policy.decide("JWT") == "mask"
    assert policy.decide("TOKEN") == "mask"

    # Unknown type defaults to mask
    assert policy.decide("UNKNOWN_NEW_ENTITY") == "mask"

    # Strict profile blocks credentials
    strict_policy = PolicyEngine(profile="strict")
    assert strict_policy.decide("CARD") == "mask"
    assert strict_policy.decide("CARD_MASKED") == "allow"
    assert strict_policy.decide("PASSWORD") == "block"
    assert strict_policy.decide("OTP") == "block"
    assert strict_policy.decide("API_KEY") == "block"
    assert strict_policy.decide("JWT") == "block"
    assert strict_policy.decide("TOKEN") == "block"


def test_url_scrubbing() -> None:
    """Test URL scrubbing of query parameters and fragment removal."""
    url = "https://sub.portal.com/app/checkout?token=secret123&session=abc456#details"
    scrubbed = scrub_url(url)
    assert scrubbed == "https://sub.portal.com/app/checkout?token=%5BREDACTED%3APARAM%5D&session=%5BREDACTED%3APARAM%5D"
    assert "secret123" not in scrubbed
    assert "#details" not in scrubbed


def test_detect_text_api() -> None:
    """Test plain string detection without DOM."""
    text = "Please reach out to support@privacylens.test or call +1-555-839-2041."
    findings = detect_text(text)
    types = [f.type for f in findings]
    assert "EMAIL" in types
    assert "PHONE" in types


def test_sanitize_plain_text_mask_and_block() -> None:
    """Test text sanitization with masking and blocking."""
    vault = Vault()
    policy = PolicyEngine()

    # Masking in default profile
    text = "Account contact email is support@example.com."
    sanitized, redactions, blocked, reason = sanitize_plain_text(text, vault, policy)
    assert not blocked
    assert "support@example.com" not in sanitized
    assert "[REDACTED:EMAIL_1]" in sanitized
    assert len(redactions) == 1

    # In default profile, API_KEY is masked (not blocked)
    secret_text = "Here is the master API key: " + "AKIA" + "IOSFODNN7EXAMPLE"
    s_mask, r_mask, blocked_def, reason_def = sanitize_plain_text(secret_text, vault, policy)
    assert not blocked_def
    assert "[REDACTED:API_KEY_1]" in s_mask

    # In strict profile, API_KEY is blocked
    strict_policy = PolicyEngine(profile="strict")
    s_block, r_block, blocked_strict, reason_strict = sanitize_plain_text(
        secret_text, vault, strict_policy
    )
    assert blocked_strict
    assert "Policy blocked" in (reason_strict or "")
