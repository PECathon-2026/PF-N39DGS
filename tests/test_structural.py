"""Unit tests for DOM structural and semantic detection rules."""

from privacylens.capture import ElementSnapshot
from privacylens.detect.structural import StructuralDetector


def test_structural_password() -> None:
    """Test password input detection."""
    detector = StructuralDetector()
    elem = ElementSnapshot(
        element_id="password-input",
        tag="input",
        input_type="password",
        autocomplete="current-password",
    )
    findings = detector.detect([elem])
    assert len(findings) == 1
    assert findings[0].type == "PASSWORD"
    assert findings[0].rule_id == "dom_type_password"


def test_structural_autocomplete() -> None:
    """Test autocomplete attribute mappings."""
    detector = StructuralDetector()
    elems = [
        ElementSnapshot(element_id="card-num", tag="input", autocomplete="cc-number"),
        ElementSnapshot(element_id="otp-code", tag="input", autocomplete="one-time-code"),
        ElementSnapshot(element_id="user-email", tag="input", autocomplete="email"),
    ]
    findings = detector.detect(elems)
    types = [f.type for f in findings]
    assert "CARD" in types
    assert "OTP" in types
    assert "EMAIL" in types


def test_structural_face_avatar() -> None:
    """Test avatar / video tile face detection."""
    detector = StructuralDetector()
    elem = ElementSnapshot(
        element_id="avatar-1",
        tag="svg",
        aria_label="Participant profile avatar",
        bbox=(10.0, 10.0, 110.0, 110.0),
    )
    findings = detector.detect([elem])
    assert len(findings) == 1
    assert findings[0].type == "FACE"
    assert findings[0].rule_id == "dom_avatar_face"


def test_structural_name_and_label_hints() -> None:
    """Test keyword hints in element label or placeholder."""
    detector = StructuralDetector()
    elem = ElementSnapshot(
        element_id="cvv-box",
        tag="input",
        associated_label_text="Card Security Code (CVV)",
    )
    findings = detector.detect([elem])
    assert any(f.type == "CVV" for f in findings)


def test_structural_ignores_label_elements() -> None:
    """Ensure UI <label> elements are never flagged as sensitive."""
    detector = StructuralDetector()
    elems = [
        ElementSnapshot(element_id="lbl-1", tag="label", visible_text="Credit Card Number"),
        ElementSnapshot(element_id="lbl-2", tag="label", visible_text="Security Code (CVV)"),
        ElementSnapshot(element_id="lbl-3", tag="label", visible_text="One-Time Password (OTP)"),
    ]
    findings = detector.detect(elems)
    assert len(findings) == 0


def test_structural_password_cvv_special_case() -> None:
    """Test masked CVV input field detection."""
    detector = StructuralDetector()
    elem = ElementSnapshot(
        element_id="card-cvv",
        tag="input",
        input_type="password",
        name="card_cvv",
    )
    findings = detector.detect([elem])
    assert len(findings) == 1
    assert findings[0].type == "CVV"
    assert findings[0].rule_id == "dom_hint_cvv"


def test_structural_password_toggle_hint() -> None:
    """Test detection of password field shown as plain text via toggle."""
    detector = StructuralDetector()
    elem = ElementSnapshot(
        element_id="toggle-field",
        tag="input",
        input_type="text",
        aria_label="Account Access Password",
    )
    findings = detector.detect([elem])
    assert any(f.type == "PASSWORD" for f in findings)


def test_structural_shipping_address_hint() -> None:
    """Regression test: verify shipping and street address hints detect ADDRESS."""
    detector = StructuralDetector()
    elem = ElementSnapshot(
        element_id="shipping-address",
        tag="input",
        name="shipping_address",
    )
    findings = detector.detect([elem])
    assert len(findings) == 1
    assert findings[0].type == "ADDRESS"
    assert findings[0].rule_id == "dom_hint_address"
    assert findings[0].is_structural is True

