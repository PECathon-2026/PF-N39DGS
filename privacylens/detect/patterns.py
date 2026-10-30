"""Regex and checksum-validated pattern detectors for sensitive entities."""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import Any

from privacylens.detect.base import Detector, register_detector
from privacylens.detect.checksums import luhn_valid, pan_valid, verhoeff_valid
from privacylens.models import Finding

logger = logging.getLogger(__name__)

# Precompiled regular expressions
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PAN_RE = re.compile(r"\b[A-Za-z]{5}[0-9]{4}[A-Za-z]\b")
_AADHAAR_CANDIDATE_RE = re.compile(
    r"(?<![a-zA-Z0-9_])[2-9]\d{3}[-\s]?\d{4}[-\s]?\d{4}(?![a-zA-Z0-9_])"
)
_CARD_CANDIDATE_RE = re.compile(r"(?<!\d)(?:\d[-\s]?){13,19}(?!\d)")

_SK_KEY_RE = re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")
_CANARY_RE = re.compile(r"\bCANARY-[0-9A-Za-z_-]{8,}\b")
_AKIA_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_GHP_RE = re.compile(r"\bghp_[A-Za-z0-9]{36}\b")
_AIZA_RE = re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")
_TOKEN_PREFIX_RE = re.compile(r"\b(?:tok|sec|key)_[A-Za-z0-9_]{12,}\b")
_HIGH_ENTROPY_KEY_RE = re.compile(
    r"(?:api[_-]?key|secret|token|auth)\s*[:=]\s*['\"]?([A-Za-z0-9_.-]{16,})['\"]?",
    re.IGNORECASE,
)

_IPV4_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
_IPV6_RE = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b")

# Phone patterns: Indian (+91 or 10-digit 6-9) and International formats
_PHONE_INDIA_RE = re.compile(r"(?<!\d)(?:\+91[-\s]?)?[6-9]\d{4}[-\s]?\d{5}(?!\d)")
_PHONE_INTL_RE = re.compile(
    r"(?<!\d)(?:\+?1[-\s]?)?(?:\([2-9]\d{2}\)|[2-9]\d{2})[-\s]?[2-9]\d{2}[-\s]?\d{4}(?!\d)"
)

# Context-dependent patterns
_OTP_RE = re.compile(r"\b\d{4,8}\b")
_OTP_CONTEXT_RE = re.compile(
    r"(?:otp|one[- ]?time|verification[- ]?code|auth[- ]?code|"
    r"security[- ]?code|login[- ]?code|passcode|authenticator)",
    re.IGNORECASE,
)

_CVV_RE = re.compile(r"\b\d{3,4}\b")
_CVV_CONTEXT_RE = re.compile(r"(?:cvv|cvc|security[- ]?code|card[- ]?code)", re.IGNORECASE)


@register_detector
class PatternDetector(Detector):
    """Detects sensitive entities via regex patterns reinforced with checksum validations."""

    @property
    def name(self) -> str:
        """Detector unique identifier."""
        return "pattern"

    def detect(self, context: Any) -> list[Finding]:
        """Scan input text or snapshot context for sensitive patterns.

        Args:
            context: Text string, PageSnapshot, ElementSnapshot, or list of strings.

        Returns:
            List of detected sensitive findings.
        """
        # If context is PageSnapshot or ElementSnapshot, detect across all visible texts
        if hasattr(context, "elements"):
            # PageSnapshot
            findings: list[Finding] = []
            for elem in context.elements:
                target_text = elem.input_value if elem.input_value else elem.visible_text
                if not target_text and elem.placeholder:
                    target_text = elem.placeholder
                if not target_text and not (elem.tag == "a" and getattr(elem, "href", None)):
                    continue
                # Add contextual hints from element label, name, placeholder
                context_hint = " ".join(
                    filter(
                        None,
                        [
                            elem.name,
                            elem.associated_label_text,
                            elem.placeholder,
                            elem.autocomplete,
                            elem.element_id,
                        ],
                    )
                )
                if target_text:
                    elem_findings = self.detect_text(
                        target_text,
                        element_id=elem.element_id,
                        context_hint=context_hint,
                        bbox=elem.bbox,
                    )
                    findings.extend(elem_findings)
                if elem.tag == "a" and getattr(elem, "href", None):
                    href_findings = self.detect_text(
                        elem.href,
                        element_id=elem.element_id,
                        context_hint=context_hint,
                        bbox=elem.bbox,
                    )
                    findings.extend(href_findings)
            return findings

        if hasattr(context, "visible_text") or hasattr(context, "input_value"):
            # Single ElementSnapshot
            target_text = context.input_value if context.input_value else context.visible_text
            if not target_text:
                return []
            context_hint = " ".join(
                filter(
                    None,
                    [
                        context.name,
                        context.associated_label_text,
                        context.placeholder,
                        context.autocomplete,
                        context.element_id,
                    ],
                )
            )
            return self.detect_text(
                target_text,
                element_id=context.element_id,
                context_hint=context_hint,
                bbox=context.bbox,
            )

        if isinstance(context, str):
            return self.detect_text(context)

        return []

    def detect_text(
        self,
        text: str,
        element_id: str | None = None,
        context_hint: str = "",
        bbox: tuple[float, float, float, float] | None = None,
    ) -> list[Finding]:
        """Detect sensitive patterns within a specific text segment."""
        findings: list[Finding] = []

        # 1. API_KEY & SECRETS
        for m in _SK_KEY_RE.finditer(text):
            findings.append(
                Finding(
                    type="API_KEY",
                    start=m.start(),
                    end=m.end(),
                    bbox=bbox,
                    confidence=1.0,
                    source="pattern",
                    rule_id="pattern_api_key_sk",
                    element_id=element_id,
                )
            )
        for m in _CANARY_RE.finditer(text):
            findings.append(
                Finding(
                    type="NOTE_WITH_CANARY",
                    start=m.start(),
                    end=m.end(),
                    bbox=bbox,
                    confidence=1.0,
                    source="pattern",
                    rule_id="pattern_canary",
                    element_id=element_id,
                )
            )
        for m in _AKIA_KEY_RE.finditer(text):
            findings.append(
                Finding(
                    type="API_KEY",
                    start=m.start(),
                    end=m.end(),
                    bbox=bbox,
                    confidence=1.0,
                    source="pattern",
                    rule_id="pattern_api_key_akia",
                    element_id=element_id,
                )
            )
        for m in _JWT_RE.finditer(text):
            findings.append(
                Finding(
                    type="JWT",
                    start=m.start(),
                    end=m.end(),
                    bbox=bbox,
                    confidence=1.0,
                    source="pattern",
                    rule_id="pattern_jwt",
                    element_id=element_id,
                )
            )
        for m in _GHP_RE.finditer(text):
            findings.append(
                Finding(
                    type="API_KEY",
                    start=m.start(),
                    end=m.end(),
                    bbox=bbox,
                    confidence=1.0,
                    source="pattern",
                    rule_id="pattern_api_key_ghp",
                    element_id=element_id,
                )
            )
        for m in _AIZA_RE.finditer(text):
            findings.append(
                Finding(
                    type="API_KEY",
                    start=m.start(),
                    end=m.end(),
                    bbox=bbox,
                    confidence=1.0,
                    source="pattern",
                    rule_id="pattern_api_key_aiza",
                    element_id=element_id,
                )
            )
        for m in _TOKEN_PREFIX_RE.finditer(text):
            findings.append(
                Finding(
                    type="TOKEN",
                    start=m.start(),
                    end=m.end(),
                    bbox=bbox,
                    confidence=0.95,
                    source="pattern",
                    rule_id="pattern_token_prefix",
                    element_id=element_id,
                )
            )
        for m in _HIGH_ENTROPY_KEY_RE.finditer(text):
            if m.start() > 0 and text[m.start() - 1] == "[":
                close_bracket = text.find("]", m.end())
                if close_bracket != -1 and close_bracket - m.end() < 2:
                    continue
            val = m.group(1)
            findings.append(
                Finding(
                    type="API_KEY",
                    start=m.start(1),
                    end=m.end(1),
                    bbox=bbox,
                    confidence=0.9,
                    source="pattern",
                    rule_id="pattern_api_key_context",
                    element_id=element_id,
                )
            )

        # 2. PAN (Indian Income Tax ID)
        for m in _PAN_RE.finditer(text):
            val = m.group()
            if pan_valid(val):
                findings.append(
                    Finding(
                        type="PAN",
                        start=m.start(),
                        end=m.end(),
                        bbox=bbox,
                        confidence=1.0,
                        source="pattern",
                        rule_id="pattern_pan_checksum",
                        element_id=element_id,
                    )
                )

        # 3. AADHAAR (Indian UIDAI with Verhoeff verification)
        for m in _AADHAAR_CANDIDATE_RE.finditer(text):
            val = m.group()
            clean = val.replace(" ", "").replace("-", "")
            if len(clean) == 12 and int(clean[0]) in range(2, 10):
                if verhoeff_valid(clean):
                    findings.append(
                        Finding(
                            type="AADHAAR",
                            start=m.start(),
                            end=m.end(),
                            bbox=bbox,
                            confidence=1.0,
                            source="pattern",
                            rule_id="pattern_aadhaar_verhoeff",
                            element_id=element_id,
                        )
                    )

        # 4. CARD (Payment Card Numbers with Luhn verification)
        for m in _CARD_CANDIDATE_RE.finditer(text):
            val = m.group()
            clean = val.replace(" ", "").replace("-", "")
            if 13 <= len(clean) <= 19 and luhn_valid(clean):
                findings.append(
                    Finding(
                        type="CARD",
                        start=m.start(),
                        end=m.end(),
                        bbox=bbox,
                        confidence=1.0,
                        source="pattern",
                        rule_id="pattern_card_luhn",
                        element_id=element_id,
                    )
                )

        # 5. EMAIL
        for m in _EMAIL_RE.finditer(text):
            findings.append(
                Finding(
                    type="EMAIL",
                    start=m.start(),
                    end=m.end(),
                    bbox=bbox,
                    confidence=0.98,
                    source="pattern",
                    rule_id="pattern_email",
                    element_id=element_id,
                )
            )

        # 6. PHONE
        for m in _PHONE_INDIA_RE.finditer(text):
            findings.append(
                Finding(
                    type="PHONE",
                    start=m.start(),
                    end=m.end(),
                    bbox=bbox,
                    confidence=0.9,
                    source="pattern",
                    rule_id="pattern_phone_in",
                    element_id=element_id,
                )
            )
        for m in _PHONE_INTL_RE.finditer(text):
            findings.append(
                Finding(
                    type="PHONE",
                    start=m.start(),
                    end=m.end(),
                    bbox=bbox,
                    confidence=0.9,
                    source="pattern",
                    rule_id="pattern_phone_intl",
                    element_id=element_id,
                )
            )

        # 7. IP ADDRESSES (IPv4 & IPv6)
        for m in _IPV4_RE.finditer(text):
            val = m.group()
            # Skip if immediately preceded by version / release keywords
            pre_text = text[max(0, m.start() - 15) : m.start()].lower()
            if re.search(r"\b(?:version|release|build|v)[ \t:=]*$", pre_text):
                continue
            if val.split(".") == ["1", "2", "3", "4"]:
                continue
            try:
                ip_obj = ipaddress.IPv4Address(val)
                parts = val.split(".")
                if len(parts) == 4 and not ip_obj.is_multicast:
                    findings.append(
                        Finding(
                            type="IP",
                            start=m.start(),
                            end=m.end(),
                            bbox=bbox,
                            confidence=0.95,
                            source="pattern",
                            rule_id="pattern_ipv4",
                            element_id=element_id,
                        )
                    )
            except ValueError:
                pass

        for m in _IPV6_RE.finditer(text):
            val = m.group()
            try:
                ipaddress.IPv6Address(val)
                findings.append(
                    Finding(
                        type="IP",
                        start=m.start(),
                        end=m.end(),
                        bbox=bbox,
                        confidence=0.95,
                        source="pattern",
                        rule_id="pattern_ipv6",
                        element_id=element_id,
                    )
                )
            except ValueError:
                pass

        hint_str = context_hint or ""

        # 8. OTP (4-8 digits when context matches)
        if _OTP_CONTEXT_RE.search(hint_str):
            for m in _OTP_RE.finditer(text):
                findings.append(
                    Finding(
                        type="OTP",
                        start=m.start(),
                        end=m.end(),
                        bbox=bbox,
                        confidence=0.95,
                        source="pattern",
                        rule_id="pattern_otp_context",
                        element_id=element_id,
                    )
                )
        else:
            for m in _OTP_RE.finditer(text):
                local_window = text[max(0, m.start() - 40) : min(len(text), m.end() + 40)]
                if _OTP_CONTEXT_RE.search(local_window):
                    findings.append(
                        Finding(
                            type="OTP",
                            start=m.start(),
                            end=m.end(),
                            bbox=bbox,
                            confidence=0.95,
                            source="pattern",
                            rule_id="pattern_otp_context",
                            element_id=element_id,
                        )
                    )

        # 9. CVV (3-4 digits when context matches)
        if _CVV_CONTEXT_RE.search(hint_str):
            for m in _CVV_RE.finditer(text):
                findings.append(
                    Finding(
                        type="CVV",
                        start=m.start(),
                        end=m.end(),
                        bbox=bbox,
                        confidence=0.95,
                        source="pattern",
                        rule_id="pattern_cvv_context",
                        element_id=element_id,
                    )
                )
        else:
            for m in _CVV_RE.finditer(text):
                start, end = m.start(), m.end()
                if start > 0 and text[start - 1] in ".:/":
                    continue
                if end < len(text) and text[end] in ".:/":
                    continue
                local_window = text[max(0, start - 30) : min(len(text), end + 30)]
                if _CVV_CONTEXT_RE.search(local_window):
                    findings.append(
                        Finding(
                            type="CVV",
                            start=start,
                            end=end,
                            bbox=bbox,
                            confidence=0.95,
                            source="pattern",
                            rule_id="pattern_cvv_context",
                            element_id=element_id,
                        )
                    )

        return findings
