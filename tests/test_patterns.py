"""Unit tests for pattern detection rules and checksum-validated entities."""

from privacylens.detect.patterns import PatternDetector


def test_pattern_aadhaar_and_decoy() -> None:
    """Test valid Aadhaar detection and rejection of checksum-failing order ID decoys."""
    detector = PatternDetector()

    valid_aadhaar_text = "Client UIDAI is 585708393474 for KYC."
    findings = detector.detect_text(valid_aadhaar_text)
    assert len(findings) == 1
    assert findings[0].type == "AADHAAR"
    assert findings[0].rule_id == "pattern_aadhaar_verhoeff"

    # Decoy 12-digit order id that fails Verhoeff
    decoy_order_id = "Order confirmation reference: 987654321013."
    findings = detector.detect_text(decoy_order_id)
    aadhaar_findings = [f for f in findings if f.type == "AADHAAR"]
    assert len(aadhaar_findings) == 0


def test_pattern_card_and_decoy() -> None:
    """Test valid payment card detection and rejection of checksum-failing tracking numbers."""
    detector = PatternDetector()

    valid_card_text = "Charged to Visa 4676336067708530 successfully."
    findings = detector.detect_text(valid_card_text)
    assert len(findings) == 1
    assert findings[0].type == "CARD"
    assert findings[0].rule_id == "pattern_card_luhn"

    # Decoy 16-digit tracking number that fails Luhn
    decoy_tracking = "Package tracking number is 9999888877776660."
    findings = detector.detect_text(decoy_tracking)
    card_findings = [f for f in findings if f.type == "CARD"]
    assert len(card_findings) == 0


def test_pattern_pan() -> None:
    """Test Indian PAN detection."""
    detector = PatternDetector()

    valid_pan_text = "Verified PAN number ABCPE1234F on file."
    findings = detector.detect_text(valid_pan_text)
    assert len(findings) == 1
    assert findings[0].type == "PAN"

    invalid_pan_text = "Reference code ABCDE1234F."
    findings = detector.detect_text(invalid_pan_text)
    pan_findings = [f for f in findings if f.type == "PAN"]
    assert len(pan_findings) == 0


def test_pattern_api_keys_and_jwt() -> None:
    """Test detection of modern API keys, tokens, and JWTs."""
    detector = PatternDetector()

    sk_key = "OpenAI key " + "sk-" + "live-CANARY-7f8a9b0c-998877665544"
    findings = detector.detect_text(sk_key)
    assert any(f.type == "API_KEY" and "sk" in f.rule_id for f in findings)

    akia_key = "AWS Access Key " + "AKIA" + "IOSFODNN7EXAMPLE"
    findings = detector.detect_text(akia_key)
    assert any(f.type == "API_KEY" and "akia" in f.rule_id for f in findings)

    jwt_token = (
        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIFRlc3RlciIsImlhdCI6MTUxNjIzOTAyMn0."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    findings = detector.detect_text(jwt_token)
    assert any(f.type == "JWT" for f in findings)


def test_pattern_email_and_phone() -> None:
    """Test detection of email addresses and phone numbers."""
    detector = PatternDetector()

    contact = "Email alex.CANARY-a1b2c3d4@example.com, phone +1-555-839-2041 or +91-98765-43210"
    findings = detector.detect_text(contact)

    email_findings = [f for f in findings if f.type == "EMAIL"]
    phone_findings = [f for f in findings if f.type == "PHONE"]
    assert len(email_findings) == 1
    assert len(phone_findings) >= 1


def test_pattern_ip_address_and_version_decoy() -> None:
    """Test IPv4 detection without false positives on version numbers."""
    detector = PatternDetector()

    text = "Gateway IP 192.168.1.105 and release version v2.14.0"
    findings = detector.detect_text(text)
    ip_findings = [f for f in findings if f.type == "IP"]
    assert len(ip_findings) == 1
    assert findings[0].start is not None


def test_pattern_otp_and_cvv_with_context() -> None:
    """Test OTP and CVV detection with semantic context."""
    detector = PatternDetector()

    otp_text = "Your one-time verification code is 738291"
    findings = detector.detect_text(otp_text, context_hint="otp authenticator code")
    assert any(f.type == "OTP" for f in findings)

    cvv_text = "842"
    findings = detector.detect_text(cvv_text, context_hint="card cvv security code")
    assert any(f.type == "CVV" for f in findings)
