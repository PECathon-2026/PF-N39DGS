from __future__ import annotations

import io
import os
import sys
from unittest.mock import patch
import pytest
from PIL import Image, ImageDraw, ImageFont

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.detect import face_layer
from core.detect.regex_layer import Finding
from core.egress.guard import (
    GuardResult,
    add_blocked_event_listener,
    check_payload,
    clear_blocked_events,
    clear_vault_values,
    disable_sanitization,
    get_blocked_events,
    is_sanitization_enabled,
    register_vault_value,
    remove_blocked_event_listener,
    set_sanitization_enabled,
)
from core.sanitize import mask_image_bytes, sanitize_text
from eval.canaries.registry import generate_registry


def _create_text_image(text: str, width: int = 600, height: int = 120) -> bytes:
    """Helper to render text clearly on an image for OCR testing."""
    img = Image.new("RGB", (width, height), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype("arial.ttf", 24)
    except Exception:
        font = ImageFont.load_default()
    draw.text((20, 35), text, fill=(0, 0, 0), font=font)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_clean_payload_passes():
    clear_blocked_events()

    # 1. Normal clean prompt
    res = check_payload("Please click the Add to Cart button and confirm.")
    assert res.passed is True
    assert res.category_counts == {}
    assert res.reason is None

    # 2. Text with valid [REDACTED:CATEGORY] placeholders
    clean_sanitized = (
        "User [REDACTED:NAME] submitted [REDACTED:CARD] from IP [REDACTED:IP] "
        "with email [REDACTED:EMAIL] and password [REDACTED:PASSWORD]."
    )
    res_san = check_payload(clean_sanitized)
    assert res_san.passed is True
    assert res_san.category_counts == {}
    assert res_san.reason is None

    # 3. Clean image with non-sensitive text
    clean_img_bytes = _create_text_image("Welcome to our online store. All rights reserved.")
    res_img = check_payload("Order summary view", image_bytes=clean_img_bytes)
    assert res_img.passed is True
    assert res_img.category_counts == {}

    # No blocked events emitted for clean payloads
    assert len(get_blocked_events()) == 0


def test_each_category_blocked():
    reg = generate_registry(101)
    clear_blocked_events()

    # Mapping of category to test string
    category_test_cases = {
        "CARD": f"Payment with card {reg.by_category('CARD')[0].value}",
        "AADHAAR": f"Identity Aadhaar {reg.by_category('AADHAAR')[0].value}",
        "PAN": f"Tax PAN {reg.by_category('PAN')[0].value}",
        "EMAIL": f"Contact email {reg.by_category('EMAIL')[0].value}",
        "PHONE": f"Call us at {reg.by_category('PHONE')[0].value}",
        "PASSWORD": f"Credentials {reg.by_category('PASSWORD')[0].value}",
        "OTP": f"Your verification code is {reg.by_category('OTP')[0].value} for login OTP",
        "API_KEY": f"Authorization: Bearer {reg.by_category('API_KEY')[0].value}",
        "IP": f"Server IP is {reg.by_category('IP')[0].value}",
        "NAME": f"Welcome user {reg.by_category('NAME')[0].value}",
        "ADDRESS": f"Deliver to {reg.by_category('ADDRESS')[0].value}",
    }

    for cat, raw_payload in category_test_cases.items():
        res = check_payload(raw_payload)
        assert res.passed is False, f"Guard failed to block category {cat}"
        assert cat in res.category_counts, f"Category {cat} not reported in category_counts: {res.category_counts}"
        assert res.category_counts[cat] >= 1

        # Non-negotiable invariant: raw value NEVER in reason
        raw_val = reg.by_category(cat)[0].value
        assert raw_val not in (res.reason or ""), f"Raw value leaked in guard reason for category {cat}"

    # Test VAULT_SECRET category
    clear_vault_values()
    register_vault_value("VAULT_CUSTOM_TOKEN", "super-secret-vault-token-xyz")
    res_vault = check_payload("Outgoing payload contains super-secret-vault-token-xyz inside")
    assert res_vault.passed is False
    assert "CUSTOM_TOKEN" in res_vault.category_counts or "VAULT_SECRET" in res_vault.category_counts
    assert "super-secret-vault-token-xyz" not in (res_vault.reason or "")
    clear_vault_values()

    # Test FACE category on image
    # Load synthetic face image from test fixtures
    face_img_path = os.path.join(os.path.dirname(__file__), "pages", "synthetic_face.png")
    if os.path.exists(face_img_path):
        with open(face_img_path, "rb") as f:
            face_bytes = f.read()
        res_face = check_payload("Participant video", image_bytes=face_bytes)
        assert res_face.passed is False
        assert "FACE" in res_face.category_counts
        assert res_face.category_counts["FACE"] >= 1


def test_unmasked_canary_in_image_blocked():
    reg = generate_registry(202)
    card_canary = reg.by_category("CARD")[0].value

    # Create unmasked image with rendered card number
    img_bytes = _create_text_image(f"Card: {card_canary}", width=600, height=120)

    # 1. Unmasked image MUST be blocked by Re-OCR guard
    res_unmasked = check_payload("View checkout screen", image_bytes=img_bytes)
    assert res_unmasked.passed is False
    assert "CARD" in res_unmasked.category_counts
    assert card_canary not in (res_unmasked.reason or "")

    # 2. Masked image (opaque blackout over the card region) MUST pass
    # Simulate finding over card text box (approximate coordinates in 600x120 image)
    finding = Finding(
        category="CARD",
        location={"x": 15, "y": 25, "w": 550, "h": 60, "width": 550, "height": 60},
        layer="ocr",
        confidence=0.95,
    )
    masked_bytes = mask_image_bytes(img_bytes, [finding], padding=5)

    res_masked = check_payload("View checkout screen", image_bytes=masked_bytes)
    assert res_masked.passed is True
    assert res_masked.category_counts == {}
    assert res_masked.reason is None


def test_guard_exception_blocks():
    clear_blocked_events()

    # 1. Corrupted image bytes triggers fail-closed block
    corrupt_bytes = b"NOT_A_VALID_PNG_OR_JPEG_IMAGE_DATA"
    res_corrupt = check_payload("Here is the screenshot", image_bytes=corrupt_bytes)

    assert res_corrupt.passed is False
    assert res_corrupt.category_counts.get("GUARD_ERROR", 0) >= 1
    assert "Guard exception:" in (res_corrupt.reason or "")
    assert str(corrupt_bytes) not in (res_corrupt.reason or "")

    # 2. Mocked unexpected exception during scanning fails closed
    with patch("core.egress.guard.scan_text", side_effect=RuntimeError("Simulated scanner crash")):
        res_crash = check_payload("Normal text")
        assert res_crash.passed is False
        assert res_crash.category_counts.get("GUARD_ERROR", 0) >= 1
        assert "RuntimeError" in (res_crash.reason or "")


def test_disabled_sanitization_blocks_and_emits_event():
    reg = generate_registry(303)
    card_val = reg.by_category("CARD")[0].value
    pan_val = reg.by_category("PAN")[0].value
    clear_blocked_events()

    captured_events = []

    def on_block(evt):
        captured_events.append(evt)

    add_blocked_event_listener(on_block)

    try:
        # Test sanitization disabled context
        with disable_sanitization():
            assert is_sanitization_enabled() is False

            # Because sanitization is disabled, raw values are NOT replaced
            raw_payload = f"Customer card is {card_val} and PAN is {pan_val}"
            sanitized = sanitize_text(raw_payload)
            assert sanitized == raw_payload  # Unsanitized!

            # The egress guard MUST catch the leakage and BLOCK
            guard_res = check_payload(sanitized)
            assert guard_res.passed is False
            assert "CARD" in guard_res.category_counts
            assert "PAN" in guard_res.category_counts

            # Verify no raw sensitive data in reason
            assert card_val not in guard_res.reason
            assert pan_val not in guard_res.reason

        # Ensure sanitization is automatically restored after context exits
        assert is_sanitization_enabled() is True

        # Now with sanitization re-enabled, sanitize_text properly replaces values
        clean_text = sanitize_text(raw_payload)
        assert card_val not in clean_text
        assert pan_val not in clean_text
        assert "[REDACTED:CARD]" in clean_text
        assert "[REDACTED:PAN]" in clean_text

        # Re-enabled sanitized payload passes guard
        clean_res = check_payload(clean_text)
        assert clean_res.passed is True

        # Verify structured blocked events captured by dashboard listener
        assert len(captured_events) >= 1
        last_event = captured_events[-1]
        assert last_event["stage"] == "EGRESS_GUARD"
        assert last_event["status"] == "BLOCKED"
        assert last_event["passed"] is False
        assert "CARD" in last_event["category_counts"]
        assert "PAN" in last_event["category_counts"]

        # Invariant: Structured event NEVER contains raw canary values
        event_str = str(last_event)
        assert card_val not in event_str
        assert pan_val not in event_str

    finally:
        remove_blocked_event_listener(on_block)
        set_sanitization_enabled(True)
