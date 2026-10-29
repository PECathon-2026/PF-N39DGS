from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List


@dataclass
class Finding:
    category: str
    location: object
    layer: str
    confidence: float


SENSITIVE_AUTOCOMPLETE = {"cc-number", "cc-csc", "cc-exp", "one-time-code", "current-password", "new-password"}


def scan_dom(snapshot: dict) -> List[Finding]:
    findings: List[Finding] = []
    for el in snapshot.get("elements", []):
        tag = (el.get("tag") or "").lower()
        typ = (el.get("type") or "").lower()
        ac = (el.get("autocomplete") or "").lower()
        name = (el.get("name") or "").lower()
        aria = (el.get("aria_label") or "").lower()
        eid = (el.get("id") or "").lower()
        if tag == "input" and typ == "password":
            findings.append(Finding("PASSWORD", {"element": el.get("el_id")}, "dom", 0.99))
        if ac in SENSITIVE_AUTOCOMPLETE:
            cat = "CARD" if "cc" in ac else ("OTP" if ac == "one-time-code" else "PASSWORD")
            findings.append(Finding(cat, {"element": el.get("el_id")}, "dom", 0.95))
        hint = " ".join([name, aria, eid])
        if any(k in hint for k in ("password", "passwd", "pwd")):
            findings.append(Finding("PASSWORD", {"element": el.get("el_id")}, "dom", 0.8))
        if any(k in hint for k in ("otp", "one-time", "verification")):
            findings.append(Finding("OTP", {"element": el.get("el_id")}, "dom", 0.8))
        if any(k in hint for k in ("card", "cc-number", "credit")):
            findings.append(Finding("CARD", {"element": el.get("el_id")}, "dom", 0.8))
    return findings
PY