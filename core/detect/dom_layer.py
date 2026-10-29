from __future__ import annotations

from typing import Any, List

from core.detect.regex_layer import Finding, scan_text

SENSITIVE_AUTOCOMPLETE = {
    "cc-number",
    "cc-csc",
    "cc-exp",
    "one-time-code",
    "current-password",
    "new-password",
}


def scan_dom(snapshot: dict) -> List[Finding]:
    findings: List[Finding] = []
    for el in snapshot.get("elements", []):
        el_id = el.get("el_id")
        tag = (el.get("tag") or "").lower()
        typ = (el.get("type") or "").lower()
        ac = (el.get("autocomplete") or "").lower()
        name = (el.get("name") or "").lower()
        aria = (el.get("aria_label") or "").lower()
        eid = (el.get("id") or "").lower()
        val = el.get("value") or ""
        hint = " ".join([name, aria, eid])

        if tag == "input" and typ == "password":
            findings.append(Finding("PASSWORD", {"element": el_id}, "dom", 0.99))
        elif ac in SENSITIVE_AUTOCOMPLETE:
            cat = "CARD" if "cc" in ac else ("OTP" if ac == "one-time-code" else "PASSWORD")
            findings.append(Finding(cat, {"element": el_id}, "dom", 0.95))
        elif any(k in hint for k in ("password", "passwd", "pwd")):
            findings.append(Finding("PASSWORD", {"element": el_id}, "dom", 0.85))
        elif any(k in hint for k in ("otp", "one-time", "verification")):
            findings.append(Finding("OTP", {"element": el_id}, "dom", 0.85))
        elif any(k in hint for k in ("card", "cc-number", "credit")):
            findings.append(Finding("CARD", {"element": el_id}, "dom", 0.85))
        elif any(k in hint for k in ("aadhaar", "uidai")):
            findings.append(Finding("AADHAAR", {"element": el_id}, "dom", 0.85))
        elif any(k in hint for k in ("pan", "pan-card")):
            findings.append(Finding("PAN", {"element": el_id}, "dom", 0.85))
        elif any(k in hint for k in ("api_key", "api-key", "token", "secret")):
            findings.append(Finding("API_KEY", {"element": el_id}, "dom", 0.85))
        elif any(k in hint for k in ("ip", "ip_addr", "ip-address")):
            findings.append(Finding("IP", {"element": el_id}, "dom", 0.85))
        elif any(k in hint for k in ("email", "mail")):
            findings.append(Finding("EMAIL", {"element": el_id}, "dom", 0.85))
        elif any(k in hint for k in ("phone", "mobile", "tel")):
            findings.append(Finding("PHONE", {"element": el_id}, "dom", 0.85))
        elif any(k in hint for k in ("address", "addr")):
            findings.append(Finding("ADDRESS", {"element": el_id}, "dom", 0.85))
        elif any(k in hint for k in ("name", "fullname")):
            findings.append(Finding("NAME", {"element": el_id}, "dom", 0.85))

        # Also inspect input values directly if present
        if val:
            for vf in scan_text(str(val)):
                findings.append(Finding(vf.category, {"element": el_id}, "dom", vf.confidence))

    return findings
