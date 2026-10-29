from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List

from eval.canaries.registry import verhoeff_check, luhn_check


@dataclass
class Finding:
    category: str
    location: object
    layer: str
    confidence: float


def _span(start: int, end: int) -> dict:
    return {"start": start, "end": end}


def scan_text(text: str) -> List[Finding]:
    findings: List[Finding] = []
    for m in re.finditer(r"\b\d{4}\s?\d{4}\s?\d{4}\b", text):
        raw = m.group(0).replace(" ", "")
        if verhoeff_check(raw):
            findings.append(Finding("AADHAAR", _span(m.start(), m.end()), "regex", 0.95))
    for m in re.finditer(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", text):
        findings.append(Finding("PAN", _span(m.start(), m.end()), "regex", 0.95))
    for m in re.finditer(r"\b(?:\d[ -]*?){13,19}\b", text):
        raw = re.sub(r"[ -]", "", m.group(0))
        if 13 <= len(raw) <= 19 and luhn_check(raw):
            findings.append(Finding("CARD", _span(m.start(), m.end()), "regex", 0.95))
    for m in re.finditer(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", text):
        findings.append(Finding("EMAIL", _span(m.start(), m.end()), "regex", 0.9))
    for m in re.finditer(r"(?:\+91[\s-]?)?[6-9]\d{9}\b", text):
        findings.append(Finding("PHONE", _span(m.start(), m.end()), "regex", 0.85))
    for m in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        findings.append(Finding("IP", _span(m.start(), m.end()), "regex", 0.9))
    for m in re.finditer(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b", text):
        findings.append(Finding("IP", _span(m.start(), m.end()), "regex", 0.9))
    for m in re.finditer(r"\b(?:sk|pk|api|token|secret)[_-][A-Za-z0-9_-]{16,}\b", text, re.I):
        findings.append(Finding("API_KEY", _span(m.start(), m.end()), "regex", 0.9))
    for m in re.finditer(r"\b\d{4,8}\b", text):
        window = text[max(0, m.start()-40):m.end()+40].lower()
        if any(k in window for k in ("otp", "one-time", "verification code", "code")):
            findings.append(Finding("OTP", _span(m.start(), m.end()), "regex", 0.8))
    return findings
