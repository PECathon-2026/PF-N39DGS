"""Checksum validation algorithms and synthetic data generators for PrivacyLens."""

from __future__ import annotations

import random
import re

# Verhoeff algorithm multiplication table
_VERHOEFF_D: tuple[tuple[int, ...], ...] = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)

# Verhoeff algorithm permutation table
_VERHOEFF_P: tuple[tuple[int, ...], ...] = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)

# Verhoeff inverse table
_VERHOEFF_INV: tuple[int, ...] = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)

# PAN regex pattern: 5 uppercase letters (4th in P,C,H,F,A,B,L,J,G,T), 4 digits, 1 uppercase letter
_PAN_REGEX = re.compile(r"^[A-Z]{3}[PCHFABLJGT][A-Z][0-9]{4}[A-Z]$")


def verhoeff_valid(number: str) -> bool:
    """Validate a numeric string using the Verhoeff checksum algorithm.

    Args:
        number: String representation of the number (spaces and hyphens stripped).

    Returns:
        True if the number has a valid Verhoeff checksum, False otherwise.
    """
    clean = number.replace(" ", "").replace("-", "")
    if not clean.isdigit() or len(clean) == 0:
        return False

    c = 0
    for i, digit in enumerate(reversed(clean)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(digit)]]
    return c == 0


def _compute_verhoeff_check_digit(base_digits: str) -> int:
    """Compute the Verhoeff check digit for a string of base digits."""
    c = 0
    for i, digit in enumerate(reversed(base_digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[(i + 1) % 8][int(digit)]]
    return _VERHOEFF_INV[c]


def luhn_valid(number: str) -> bool:
    """Validate a numeric string using the Luhn checksum algorithm (Mod 10).

    Args:
        number: String representation of the card/number (spaces and hyphens stripped).

    Returns:
        True if the number has a valid Luhn checksum, False otherwise.
    """
    clean = number.replace(" ", "").replace("-", "")
    if not clean.isdigit() or len(clean) < 2:
        return False

    total = 0
    reversed_digits = [int(ch) for ch in reversed(clean)]
    for i, d in enumerate(reversed_digits):
        if i % 2 == 1:
            doubled = d * 2
            total += (doubled - 9) if doubled > 9 else doubled
        else:
            total += d

    return total % 10 == 0


def _compute_luhn_check_digit(base_digits: str) -> int:
    """Compute the Luhn check digit to append to base_digits."""
    total = 0
    reversed_digits = [int(ch) for ch in reversed(base_digits)]
    for i, d in enumerate(reversed_digits):
        # In the complete number with check digit at index 0,
        # these digits start at index 1 (odd index), so they double at even i here
        if i % 2 == 0:
            doubled = d * 2
            total += (doubled - 9) if doubled > 9 else doubled
        else:
            total += d

    remainder = total % 10
    return (10 - remainder) % 10


def pan_valid(pan: str) -> bool:
    """Validate an Indian Permanent Account Number (PAN).

    Requirements:
        - 10 characters long
        - Format: 5 uppercase letters, 4 digits, 1 uppercase letter
        - 4th character must be one of: P, C, H, F, A, B, L, J, G, T

    Args:
        pan: String representation of the PAN.

    Returns:
        True if valid PAN format, False otherwise.
    """
    clean = pan.strip().upper()
    return bool(_PAN_REGEX.match(clean))


def gen_aadhaar(seed: int | None = None) -> str:
    """Generate a synthetic 12-digit Aadhaar number with valid Verhoeff checksum.

    First digit is restricted to 2-9 per UIDAI standards.

    Args:
        seed: Optional integer seed for deterministic generation.

    Returns:
        12-digit valid Aadhaar number string.
    """
    rng = random.Random(seed)
    first_digit = str(rng.randint(2, 9))
    middle_digits = "".join(str(rng.randint(0, 9)) for _ in range(10))
    base = first_digit + middle_digits
    check_digit = _compute_verhoeff_check_digit(base)
    aadhaar = base + str(check_digit)
    assert verhoeff_valid(aadhaar)
    return aadhaar


def gen_card(seed: int | None = None, prefix: str = "4") -> str:
    """Generate a synthetic 16-digit payment card number with valid Luhn checksum.

    Default prefix '4' generates a Visa-format card.

    Args:
        seed: Optional integer seed for deterministic generation.
        prefix: Starting digits of the card (default '4').

    Returns:
        16-digit valid card number string.
    """
    rng = random.Random(seed)
    needed = 15 - len(prefix)
    middle_digits = "".join(str(rng.randint(0, 9)) for _ in range(needed))
    base = prefix + middle_digits
    check_digit = _compute_luhn_check_digit(base)
    card = base + str(check_digit)
    assert luhn_valid(card)
    return card

