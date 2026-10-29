from __future__ import annotations

from typing import Any, Dict, List

from core.detect.regex_layer import Finding, scan_text

SENSITIVE_AUTOCOMPLETE = {
    "cc-number",
    "cc-csc",
    "cc-exp",
    "one-time-code",
    "current-password",
    "new-password",
}


def _loc(el: Dict[str, Any]) -> Dict[str, Any]:
    res: Dict[str, Any] = {"element": el.get("el_id")}
    box = el.get("box")
    if isinstance(box, dict) and "x" in box and "y" in box and "w" in box and "h" in box:
        res["x"] = box["x"]
        res["y"] = box["y"]
        res["w"] = box["w"]
        res["h"] = box["h"]
    return res


def scan_dom(snapshot: dict) -> List[Finding]:
    findings: List[Finding] = []
    for el in snapshot.get("elements", []):
        el_loc = _loc(el)
        tag = (el.get("tag") or "").lower()
        typ = (el.get("type") or "").lower()
        ac = (el.get("autocomplete") or "").lower()
        name = (el.get("name") or "").lower()
        aria = (el.get("aria_label") or "").lower()
        eid = (el.get("id") or "").lower()
        val = el.get("value") or ""
        hint = " ".join([name, aria, eid])

        if tag == "input" and typ == "password":
            findings.append(Finding("PASSWORD", el_loc, "dom", 0.99))
        elif ac in SENSITIVE_AUTOCOMPLETE:
            cat = "CARD" if "cc" in ac else ("OTP" if ac == "one-time-code" else "PASSWORD")
            findings.append(Finding(cat, el_loc, "dom", 0.95))
        elif any(k in hint for k in ("password", "passwd", "pwd")):
            findings.append(Finding("PASSWORD", el_loc, "dom", 0.85))
        elif any(k in hint for k in ("otp", "one-time", "verification")):
            findings.append(Finding("OTP", el_loc, "dom", 0.85))
        elif any(k in hint for k in ("card", "cc-number", "credit")):
            findings.append(Finding("CARD", el_loc, "dom", 0.85))
        elif any(k in hint for k in ("aadhaar", "uidai")):
            findings.append(Finding("AADHAAR", el_loc, "dom", 0.85))
        elif any(k in hint for k in ("pan", "pan-card")):
            findings.append(Finding("PAN", el_loc, "dom", 0.85))
        elif any(k in hint for k in ("api_key", "api-key", "token", "secret")):
            findings.append(Finding("API_KEY", el_loc, "dom", 0.85))
        elif any(k in hint for k in ("ip", "ip_addr", "ip-address")):
            findings.append(Finding("IP", el_loc, "dom", 0.85))
        elif any(k in hint for k in ("email", "mail")):
            findings.append(Finding("EMAIL", el_loc, "dom", 0.85))
        elif any(k in hint for k in ("phone", "mobile", "tel")):
            findings.append(Finding("PHONE", el_loc, "dom", 0.85))
        elif any(k in hint for k in ("address", "addr")):
            findings.append(Finding("ADDRESS", el_loc, "dom", 0.85))
        elif any(k in hint for k in ("name", "fullname")):
            findings.append(Finding("NAME", el_loc, "dom", 0.85))

        # Also inspect input values directly if present
        if val:
            for vf in scan_text(str(val)):
                findings.append(Finding(vf.category, el_loc, "dom", vf.confidence))

    return findings
