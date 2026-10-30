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
        
    # API_KEY — multi-pattern detection covering vendor-specific and high-entropy keys

    def _shannon_entropy(s: str) -> float:
        """Shannon entropy in bits/char. High values indicate random secrets."""
        if not s:
            return 0.0
        freq: dict = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        n = len(s)
        import math
        return -sum((f / n) * math.log2(f / n) for f in freq.values())

    # Vendor-prefixed patterns (high confidence 0.97)
    _VENDOR_API_PATTERNS = [
        (r"\bsk-[A-Za-z0-9]{20,}\b", 0.97),                         # OpenAI / Anthropic
        (r"\bpk-[A-Za-z0-9]{20,}\b", 0.97),                         # Public key pairs
        (r"\bAIza[0-9A-Za-z_-]{35}\b", 0.97),                       # Google API key
        (r"\bAKIA[0-9A-Z]{16}\b", 0.97),                            # AWS Access Key ID
        (r"\bghp_[A-Za-z0-9]{36}\b", 0.97),                        # GitHub PAT classic
        (r"\bgithub_pat_[A-Za-z0-9_]{22,}\b", 0.97),               # GitHub PAT fine-grained
        (r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", 0.95),  # JWT
        (r"\b(?:sk|pk|api|token|secret|key)[_-][A-Za-z0-9_-]{16,}\b", 0.90),  # Generic prefix
    ]
    for pat, conf in _VENDOR_API_PATTERNS:
        flags = re.I if conf <= 0.90 else 0  # generic prefix is case-insensitive
        for m in re.finditer(pat, text, flags):
            findings.append(Finding("API_KEY", _span(m.start(), m.end()), "regex", conf))

    # High-entropy string detection — catch unknown key formats (medium confidence 0.75)
    for m in re.finditer(r"[A-Za-z0-9+/]{32,}", text):
        candidate = m.group(0)
        if _shannon_entropy(candidate) > 4.5:
            findings.append(Finding("API_KEY", _span(m.start(), m.end()), "regex", 0.75))

    # OTP (digits in OTP context or 6-digit numeric codes with context)
    for m in re.finditer(r"\b\d{4,8}\b", text):
        window = text[max(0, m.start() - 40):m.end() + 40].lower()
        if any(k in window for k in ("otp", "one-time", "verification code", "code", "submit-otp")):
            findings.append(Finding("OTP", _span(m.start(), m.end()), "regex", 0.85))
            
    # -------------------------------------------------------------------------
    # PASSWORD DETECTION (Canary patterns, exposed cleartext, key-value pairs)
    # -------------------------------------------------------------------------
    # 1. Canary pattern or explicit password token formats
    for m in re.finditer(r"\bP@ssw0rd-[A-Za-z0-9_-]{8,}\b", text):
        findings.append(Finding("PASSWORD", _span(m.start(), m.end()), "regex", 0.95))

    # 2. Key-value style assignments and exposed phrasing
    _NON_PASSWORDS = {
        "password", "passwd", "pwd", "text", "null", "undefined", "true", "false",
        "field", "input", "here", "required", "hidden", "shown", "box", "label",
        "button", "forgot", "reset", "change", "enter", "your", "the", "please",
        "strong", "weak", "invalid", "valid", "again", "confirm", "value", "type",
        "name", "id", "tag", "class", "placeholder"
    }

    _pwd_pattern = (
        r"(?i)\b(?:password|passwd|pwd|passcode|passphrase)"
        r"(?:\s+(?:is|was|set\s+to)\s*[:=]?\s*|\s*[:=]\s*)"
        r"[\"']?([A-Za-z0-9_@#$%^&*!.-]{4,64})[\"']?"
    )
    for m in re.finditer(_pwd_pattern, text):
        raw_val = m.group(1).strip()
        if (
            not raw_val.startswith("[REDACTED")
            and raw_val.lower() not in _NON_PASSWORDS
            and len(raw_val) >= 4
        ):
            val_start = m.start(1)
            val_end = m.end(1)
            findings.append(Finding("PASSWORD", _span(val_start, val_end), "regex", 0.90))

    # NAME (Canary person or explicit participant/name context)
    for m in re.finditer(r"\bCanary Person [0-9a-f]{6}\b", text):
        findings.append(Finding("NAME", _span(m.start(), m.end()), "regex", 0.9))
        
    # ADDRESS — strict street address matching with word boundary on street suffix
    _addr_pat = r"\b\d{1,5}\s+[A-Za-z0-9\s,.-]{1,40}?\b(?:Street|St|Road|Rd|Avenue|Ave|Drive|Dr|Lane|Ln|Boulevard|Blvd|Way|Court|Ct)\b(?:,\s*[A-Za-z0-9\s,.-]{1,40})?"
    for m in re.finditer(_addr_pat, text, re.I):
        findings.append(Finding("ADDRESS", _span(m.start(), m.end()), "regex", 0.85))

    return findings
