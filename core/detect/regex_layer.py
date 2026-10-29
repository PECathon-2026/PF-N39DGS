from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List

from eval.canaries.registry import verhoeff_check, luhn_check


@dataclass
class Finding:
    category: str
    location: object
    layer: str
    confidence: float
    source_layers: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.source_layers and self.layer:
            self.source_layers = [self.layer]


def _span(start: int, end: int) -> dict:
    return {"start": start, "end": end}


def scan_text(text: str) -> List[Finding]:
    findings: List[Finding] = []
    
    # AADHAAR
    for m in re.finditer(r"\b\d{4}\s?\d{4}\s?\d{4}\b", text):
        raw = m.group(0).replace(" ", "")
        # Disambiguate: Indian mobile numbers with country code 91
        if raw.startswith("91") and len(raw) == 12 and raw[2] in "6789":
            continue
        if verhoeff_check(raw):
            findings.append(Finding("AADHAAR", _span(m.start(), m.end()), "regex", 0.95))
            
    # PAN
    for m in re.finditer(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", text):
        findings.append(Finding("PAN", _span(m.start(), m.end()), "regex", 0.95))
        
    # CARD (Luhn)
    for m in re.finditer(r"\b(?:\d[ -]*?){13,19}\b", text):
        raw = re.sub(r"[ -]", "", m.group(0))
        if 13 <= len(raw) <= 19 and luhn_check(raw):
            findings.append(Finding("CARD", _span(m.start(), m.end()), "regex", 0.95))
            
    # EMAIL
    for m in re.finditer(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", text):
        findings.append(Finding("EMAIL", _span(m.start(), m.end()), "regex", 0.9))
        
    # PHONE
    for m in re.finditer(r"(?:\+?91[\s-]?)?[6-9]\d{9}\b", text):
        findings.append(Finding("PHONE", _span(m.start(), m.end()), "regex", 0.9))
        
    # IP (IPv4 and IPv6)
    for m in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        parts = m.group(0).split(".")
        if all(0 <= int(p) <= 255 for p in parts if p.isdigit()):
            findings.append(Finding("IP", _span(m.start(), m.end()), "regex", 0.9))
    for m in re.finditer(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b", text):
        findings.append(Finding("IP", _span(m.start(), m.end()), "regex", 0.9))
        
    # API_KEY
    for m in re.finditer(r"\b(?:sk|pk|api|token|secret)[_-][A-Za-z0-9_-]{16,}\b", text, re.I):
        findings.append(Finding("API_KEY", _span(m.start(), m.end()), "regex", 0.9))
        
    # OTP (digits in OTP context or 6-digit numeric codes with context)
    for m in re.finditer(r"\b\d{4,8}\b", text):
        window = text[max(0, m.start() - 40):m.end() + 40].lower()
        if any(k in window for k in ("otp", "one-time", "verification code", "code", "submit-otp")):
            findings.append(Finding("OTP", _span(m.start(), m.end()), "regex", 0.85))
            
    # PASSWORD (specific canary pattern or password context)
    for m in re.finditer(r"\bP@ssw0rd-[A-Za-z0-9_-]{8,}\b", text):
        findings.append(Finding("PASSWORD", _span(m.start(), m.end()), "regex", 0.95))
        
    # NAME (Canary person or explicit participant/name context)
    for m in re.finditer(r"\bCanary Person [0-9a-f]{6}\b", text):
        findings.append(Finding("NAME", _span(m.start(), m.end()), "regex", 0.9))
        
    # ADDRESS
    for m in re.finditer(r"\b\d+\s+[A-Za-z0-9\s,.-]+(?:Street|St|Road|Rd|Avenue|Ave|Drive|Lane|Blvd)[A-Za-z0-9\s,.-]+\b", text, re.I):
        findings.append(Finding("ADDRESS", _span(m.start(), m.end()), "regex", 0.85))

    return findings
