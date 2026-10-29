"""Tests for checksum algorithms and synthetic generators."""

from privacylens.detect.checksums import (
    gen_aadhaar,
    gen_card,
    luhn_valid,
    pan_valid,
    verhoeff_valid,
)


def test_verhoeff_valid_and_invalid() -> None:
    """Test Verhoeff validation with known valid and invalid numbers."""
    # Standard Verhoeff test cases
    assert verhoeff_valid("2363") is True
    assert verhoeff_valid("2364") is False
    assert verhoeff_valid("123451") is True
    assert verhoeff_valid("123452") is False
    assert verhoeff_valid("123456789012") is False

    # Aadhaar format with spaces/hyphens
    generated = gen_aadhaar(seed=42)
    assert verhoeff_valid(generated) is True
    assert verhoeff_valid(f"{generated[:4]} {generated[4:8]} {generated[8:]}") is True
    assert verhoeff_valid(f"{generated[:4]}-{generated[4:8]}-{generated[8:]}") is True

    # Mutated digit should fail Verhoeff
    last_digit = int(generated[-1])
    mutated = generated[:-1] + str((last_digit + 1) % 10)
    assert verhoeff_valid(mutated) is False

    # Non-digit cases
    assert verhoeff_valid("") is False
    assert verhoeff_valid("invalid-text") is False


def test_luhn_valid_and_invalid() -> None:
    """Test Luhn algorithm with known valid and invalid numbers."""
    # Known valid test numbers
    assert luhn_valid("49927398716") is True
    assert luhn_valid("79927398713") is True
    assert luhn_valid("4111111111111111") is True

    # Generated valid card
    card = gen_card(seed=123)
    assert len(card) == 16
    assert luhn_valid(card) is True
    assert luhn_valid(f"{card[:4]} {card[4:8]} {card[8:12]} {card[12:]}") is True

    # Invalid Luhn
    assert luhn_valid("49927398717") is False
    assert luhn_valid("79927398710") is False
    assert luhn_valid("") is False
    assert luhn_valid("4") is False
    assert luhn_valid("not_a_number") is False


def test_pan_valid_and_invalid() -> None:
    """Test PAN validation logic."""
    # Valid PAN cases with permitted 4th characters: P, C, H, F, A, B, L, J, G, T
    valid_pans = [
        "ABCPE1234F",  # Valid: 4th is 'P' (Person/Individual)
        "XYZCA9876Z",  # Valid: 4th is 'C' (Company)
        "AAAHB1111A",  # Valid: 4th is 'H' (HUF)
        "BBFFA2222B",  # Valid: 4th is 'F' (Firm)
        "CCAAF3333C",  # Valid: 4th is 'A' (Association of Persons)
        "DDBLF4444D",  # Valid: 4th is 'B' (Body of Individuals)
        "EELJA5555E",  # Valid: 4th is 'L' (Local Authority)
        "FFJPA6666F",  # Valid: 4th is 'J' (Artificial Juridical Person)
        "GGGPA7777G",  # Valid: 4th is 'G' (Government)
        "THTPA8888T",  # Valid: 4th is 'T' (Trust)
    ]
    for pan in valid_pans:
        assert pan_valid(pan) is True

    # Invalid cases
    assert pan_valid("ABCDE1234F") is False  # 'D' is not allowed 4th char
    assert pan_valid("ABCPE1234") is False  # Too short
    assert pan_valid("ABCPE12345F") is False  # Too long
    assert pan_valid("123PE1234F") is False  # Starts with numbers
    assert pan_valid("ABCPEABCDA") is False  # Digits replaced by letters


def test_gen_aadhaar_properties() -> None:
    """Verify Aadhaar generator constraints."""
    for s in range(10):
        aadhaar = gen_aadhaar(seed=s)
        assert len(aadhaar) == 12
        assert aadhaar.isdigit()
        assert int(aadhaar[0]) in range(2, 10)
        assert verhoeff_valid(aadhaar) is True

    # Determinism test
    assert gen_aadhaar(seed=999) == gen_aadhaar(seed=999)


def test_gen_card_properties() -> None:
    """Verify Card generator constraints."""
    for s in range(10):
        card = gen_card(seed=s)
        assert len(card) == 16
        assert card.isdigit()
        assert card.startswith("4")
        assert luhn_valid(card) is True

    # Determinism test
    assert gen_card(seed=888) == gen_card(seed=888)
