"""DOM structural and semantic detector for browser pages."""

from __future__ import annotations

import logging
import re
from typing import Any

from privacylens.detect.base import Detector, register_detector
from privacylens.models import Finding

logger = logging.getLogger(__name__)

# Keyword patterns for attribute inspection
_HINT_PATTERNS = {
    "CVV": re.compile(r"\b(?:cvv|cvc|security[-_]?code|card[-_]?cvv)\b", re.IGNORECASE),
    "OTP": re.compile(r"\b(?:otp|one[-_]?time|authenticator)\b", re.IGNORECASE),
    "EXPIRY": re.compile(r"\b(?:exp|expiry|expiration|card[-_]?exp)\b", re.IGNORECASE),
    "CARD": re.compile(
        r"\b(?:credit|debit)?[-_]?card(?![-_]?(?:exp|expiry|cvv|csc|code))"
        r"(?:[-_]?(?:number|num|no))?\b",
        re.IGNORECASE,
    ),
    "AADHAAR": re.compile(r"\b(?:aadhaar|uidai)\b", re.IGNORECASE),
    "PAN": re.compile(r"\b(?:pan[-_]?number|pan[-_]?card)\b", re.IGNORECASE),
    "API_KEY": re.compile(r"\b(?:api[-_]?key|secret[-_]?key|access[-_]?key)\b", re.IGNORECASE),
    "TOKEN": re.compile(r"\b(?:session[-_]?token|auth[-_]?token)\b", re.IGNORECASE),
    "PASSWORD": re.compile(r"\b(?:password|passwd|pwd)\b", re.IGNORECASE),
    "ADDRESS": re.compile(
        r"\b(?:street|shipping|billing|invoice|office|home|delivery|user|company)?[-_]?address\b",
        re.IGNORECASE,
    ),
}

_AUTOCOMPLETE_MAP = {
    "cc-number": "CARD",
    "cc-csc": "CVV",
    "cc-exp": "EXPIRY",
    "one-time-code": "OTP",
    "email": "EMAIL",
    "tel": "PHONE",
    "street-address": "ADDRESS",
    "current-password": "PASSWORD",
    "new-password": "PASSWORD",
}


def _get_field(obj: Any, field_name: str, default: str = "") -> str:
    """Safely extract string field from dataclass, object, or dict."""
    if hasattr(obj, field_name):
        val = getattr(obj, field_name)
        return str(val) if val is not None else default
    if isinstance(obj, dict):
        val = obj.get(field_name)
        return str(val) if val is not None else default
    return default


@register_detector
class StructuralDetector(Detector):
    """Detects sensitive input fields and visual regions using DOM semantics."""

    @property
    def name(self) -> str:
        """Detector name identifier."""
        return "structural"

    def detect(self, context: Any) -> list[Finding]:
        """Inspect DOM element metadata for sensitive indicators.

        Args:
            context: PageSnapshot, ElementSnapshot, or dictionary of DOM elements.

        Returns:
            List of detected sensitive findings.
        """
        findings: list[Finding] = []

        elements = []
        if hasattr(context, "elements"):
            elements = context.elements
        elif isinstance(context, list):
            elements = context
        elif hasattr(context, "element_id"):
            elements = [context]

        for el in elements:
            el_id = _get_field(el, "element_id", "") or None
            tag = _get_field(el, "tag", "").lower()
            input_type = _get_field(el, "input_type", "").lower()
            autocomplete = _get_field(el, "autocomplete", "").lower()
            name = _get_field(el, "name", "").lower()
            placeholder = _get_field(el, "placeholder", "").lower()
            label = _get_field(el, "associated_label_text", "").lower()
            aria_label = _get_field(el, "aria_label", "").lower()
            bbox = getattr(el, "bbox", None) if hasattr(el, "bbox") else el.get("bbox")

            # Check whether element is an input control
            is_input_element = (
                tag in ("input", "textarea", "select")
                or bool(input_type)
                or (el.get("role") in ("textbox", "combobox") if isinstance(el, dict) else False)
            )

            combined_desc = f"{el_id or ''} {name} {placeholder} {label} {aria_label}".lower()

            # 1. Password input fields (special-case CVV/OTP masked as password)
            if input_type == "password":
                pwd_type = "PASSWORD"
                pwd_rule = "dom_type_password"
                if _HINT_PATTERNS["CVV"].search(combined_desc):
                    pwd_type = "CVV"
                    pwd_rule = "dom_hint_cvv"
                elif _HINT_PATTERNS["OTP"].search(combined_desc):
                    pwd_type = "OTP"
                    pwd_rule = "dom_hint_otp"
                findings.append(
                    Finding(
                        type=pwd_type,
                        confidence=1.0,
                        source="structural",
                        rule_id=pwd_rule,
                        element_id=el_id,
                        bbox=bbox,
                        is_structural=True,
                    )
                )
                continue

            # 2. Autocomplete attributes (only on form input elements)
            if is_input_element and autocomplete and autocomplete in _AUTOCOMPLETE_MAP:
                entity_type = _AUTOCOMPLETE_MAP[autocomplete]
                findings.append(
                    Finding(
                        type=entity_type,
                        confidence=0.98,
                        source="structural",
                        rule_id=f"dom_autocomplete_{autocomplete}",
                        element_id=el_id,
                        bbox=bbox,
                        is_structural=True,
                    )
                )
                continue

            # 3. Avatar / Face elements in participant or video containers
            if tag in ("img", "svg") and (
                "profile avatar" in combined_desc
                or "webcam" in combined_desc
                or "camera-stream" in combined_desc
            ):
                findings.append(
                    Finding(
                        type="FACE",
                        confidence=0.85,
                        source="structural",
                        rule_id="dom_avatar_face",
                        element_id=el_id,
                        bbox=bbox,
                        is_structural=True,
                    )
                )
                continue

            # 4. Keyword hints across name, id, placeholder, and label
            # Strict rule: only inspect input/data-bearing elements, NEVER UI <label> elements
            if is_input_element and tag != "label":
                for entity_type, pat in _HINT_PATTERNS.items():
                    if pat.search(combined_desc):
                        findings.append(
                            Finding(
                                type=entity_type,
                                confidence=0.9,
                                source="structural",
                                rule_id=f"dom_hint_{entity_type.lower()}",
                                element_id=el_id,
                                bbox=bbox,
                                is_structural=True,
                            )
                        )
                        break

        return findings
