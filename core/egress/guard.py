from __future__ import annotations

import base64
import io
import os
import re
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterator, List, Optional, Union

from PIL import Image
from core.detect import face_layer, ocr_layer, regex_layer
from core.detect.regex_layer import scan_text
from core.detect.ocr_layer import extract_confident_text
from core.sanitize import (
    disable_sanitization,
    is_sanitization_enabled,
    set_sanitization_enabled,
)


@dataclass
class GuardResult:
    """Result returned by the egress guard check."""

    passed: bool
    category_counts: Dict[str, int] = field(default_factory=dict)
    reason: Optional[str] = None

    def __iter__(self):
        """Enable 3-tuple unpacking: passed, category_counts, reason = check_payload(...)"""
        return iter((self.passed, self.category_counts, self.reason))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "category_counts": dict(self.category_counts),
            "reason": self.reason,
        }


# In-memory blocked event stream for dashboard and telemetry consumption
_BLOCKED_EVENTS: List[Dict[str, Any]] = []
_EVENT_LISTENERS: List[Callable[[Dict[str, Any]], None]] = []

# In-memory secret vault for symbolic value verification
_IN_MEMORY_VAULT: Dict[str, str] = {}


def register_vault_value(category_or_key: str, value: str) -> None:
    """Register a sensitive value or canary in the local vault for egress tracking."""
    _IN_MEMORY_VAULT[category_or_key] = value


def clear_vault_values() -> None:
    """Clear registered vault values."""
    _IN_MEMORY_VAULT.clear()


def get_vault_values() -> Dict[str, str]:
    """Retrieve all active vault values from memory, .env, and vault module."""
    v = dict(_IN_MEMORY_VAULT)
    try:
        from core.vault import vault as vault_mod

        if hasattr(vault_mod, "get_vault"):
            v.update(vault_mod.get_vault())
    except ImportError:
        pass

    for k, val in os.environ.items():
        if (k.startswith("VAULT_") or k.startswith("SECRET_")) and val.strip():
            v[k] = val.strip()
    return v


def get_blocked_events() -> List[Dict[str, Any]]:
    """Return a copy of all recorded blocked egress events."""
    return [dict(e) for e in _BLOCKED_EVENTS]


def clear_blocked_events() -> None:
    """Clear the recorded blocked events list."""
    _BLOCKED_EVENTS.clear()


def add_blocked_event_listener(listener: Callable[[Dict[str, Any]], None]) -> None:
    """Register a callback listener that receives each blocked event as it occurs."""
    _EVENT_LISTENERS.append(listener)


def remove_blocked_event_listener(listener: Callable[[Dict[str, Any]], None]) -> None:
    """Remove a previously registered blocked event listener."""
    if listener in _EVENT_LISTENERS:
        _EVENT_LISTENERS.remove(listener)


def _emit_blocked_event(category_counts: Dict[str, int], reason: str) -> Dict[str, Any]:
    """Emit a structured blocked event containing categories and counts only (no raw data)."""
    event = {
        "event_id": f"blk_{uuid.uuid4().hex[:12]}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "stage": "EGRESS_GUARD",
        "status": "BLOCKED",
        "passed": False,
        "category_counts": dict(category_counts),
        "reason": reason,
    }
    _BLOCKED_EVENTS.append(event)
    for listener in list(_EVENT_LISTENERS):
        try:
            listener(event)
        except Exception:
            pass
    return event


def _load_guard_image(image_input: Union[bytes, str, Image.Image]) -> Image.Image:
    """Safely load image bytes, base64 string, or filepath into a PIL Image."""
    if isinstance(image_input, Image.Image):
        return image_input
    if isinstance(image_input, bytes):
        return Image.open(io.BytesIO(image_input))
    if isinstance(image_input, str):
        if os.path.isfile(image_input):
            return Image.open(image_input)
        try:
            raw = base64.b64decode(image_input)
            return Image.open(io.BytesIO(raw))
        except Exception:
            raise ValueError("Invalid image input string: not a valid file path or base64")
    raise TypeError(f"Unsupported image input type: {type(image_input).__name__}")


def _infer_vault_category(key: str) -> str:
    """Map a vault key name to a canonical category."""
    k_upper = key.upper()
    if k_upper.startswith("VAULT_"):
        k_upper = k_upper[6:]
    elif k_upper.startswith("SECRET_"):
        k_upper = k_upper[7:]

    known_categories = {
        "CARD",
        "AADHAAR",
        "PAN",
        "EMAIL",
        "PHONE",
        "PASSWORD",
        "OTP",
        "API_KEY",
        "IP",
        "NAME",
        "ADDRESS",
        "FACE",
    }
    for known in known_categories:
        if known in k_upper:
            return known

    return k_upper if k_upper else "VAULT_SECRET"


def _scan_vault_values(
    text: str,
    vault: Optional[Union[Dict[str, str], List[str]]],
    category_counts: Dict[str, int],
) -> None:
    """Scan text for any registered vault secrets."""
    effective: Dict[str, str] = {}
    if vault is None:
        effective = get_vault_values()
    elif isinstance(vault, dict):
        effective = dict(vault)
    elif isinstance(vault, (list, set, tuple)):
        for idx, item in enumerate(vault):
            if isinstance(item, str):
                effective[f"VAULT_SECRET_{idx}"] = item

    for key, val in effective.items():
        if not val or not isinstance(val, str):
            continue
        v_str = val.strip()
        # Enforce minimum length of 3 chars to prevent false positives on tiny tokens
        if len(v_str) < 3:
            continue
        if v_str in text:
            cat = _infer_vault_category(key)
            category_counts[cat] = category_counts.get(cat, 0) + 1


def check_payload(
    text: str = "",
    image_bytes: Optional[Union[bytes, str, Image.Image]] = None,
    vault: Optional[Union[Dict[str, str], List[str]]] = None,
) -> GuardResult:
    """Pre-egress verification guard. Sole gate before transmission to external model.

    Steps:
    1. Re-run regex/validator layer on the exact outgoing text.
    2. Check vault values against outgoing text.
    3. Re-OCR the exact masked image bytes and scan the extracted text + vault + face check.
    4. Any hit or any exception means BLOCK (fail closed).
    5. Returns GuardResult(passed, category_counts, reason).
       Results and errors contain categories and counts only, never raw values.
    """
    category_counts: Dict[str, int] = {}

    try:
        out_text = text if text is not None else ""

        # Step 1: Re-run regex/validator layer on exact outgoing text
        if out_text:
            findings = scan_text(out_text)
            for f in findings:
                cat = f.category.upper()
                category_counts[cat] = category_counts.get(cat, 0) + 1

            # Step 2: Check vault values against outgoing text
            _scan_vault_values(out_text, vault, category_counts)

        # Step 3: Re-OCR exact masked image bytes and scan result
        if image_bytes is not None and image_bytes != b"" and image_bytes != "":
            img = _load_guard_image(image_bytes)

            # Re-OCR image text — use confidence-filtered extraction to suppress
            # garbage characters from solid-black redaction rectangles (these score
            # 0-50 in Tesseract and would cause false-positive BLOCK events).
            ocr_text = extract_confident_text(img, min_confidence=70)
            if ocr_text.strip():
                ocr_findings = scan_text(ocr_text)
                for f in ocr_findings:
                    cat = f.category.upper()
                    category_counts[cat] = category_counts.get(cat, 0) + 1

                _scan_vault_values(ocr_text, vault, category_counts)

            # Check if unmasked faces remain
            face_findings = face_layer.scan_image(img)
            if face_findings:
                category_counts["FACE"] = category_counts.get("FACE", 0) + len(face_findings)

        # Step 4: Any hit means BLOCK
        if category_counts:
            counts_summary = ", ".join(
                f"{k}({v})" for k, v in sorted(category_counts.items())
            )
            reason = f"Sensitive data detected: {counts_summary}"
            _emit_blocked_event(category_counts, reason)
            return GuardResult(passed=False, category_counts=category_counts, reason=reason)

        # Clean payload passes
        return GuardResult(passed=True, category_counts={}, reason=None)

    except Exception as exc:
        # Any exception in detection, OCR, or image processing means BLOCK (fail-closed)
        # Invariant: Never include raw values or input payloads in error messages
        err_counts = {"GUARD_ERROR": 1}
        reason = f"Guard exception: {type(exc).__name__}"
        _emit_blocked_event(err_counts, reason)
        return GuardResult(passed=False, category_counts=err_counts, reason=reason)


__all__ = [
    "GuardResult",
    "check_payload",
    "register_vault_value",
    "clear_vault_values",
    "get_vault_values",
    "get_blocked_events",
    "clear_blocked_events",
    "add_blocked_event_listener",
    "remove_blocked_event_listener",
    "set_sanitization_enabled",
    "is_sanitization_enabled",
    "disable_sanitization",
]
