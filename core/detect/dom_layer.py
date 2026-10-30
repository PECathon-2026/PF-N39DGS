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
        placeholder = (el.get("placeholder") or "").lower()
        cls = (el.get("class") or "").lower()
        lbl = (el.get("label") or "").lower()
        txt = (el.get("text") or "").lower()
        val = el.get("value") or ""
        val_str = str(val).strip()

        # Aggregate context clues from all relevant DOM attributes
        hint = " ".join([name, aria, eid, placeholder, cls, lbl, txt])

        # -------------------------------------------------------------
        # PASSWORD DETECTION (both masked with dots and exposed text)
        # -------------------------------------------------------------
        is_password_field = (
            typ == "password"
            or ac in ("current-password", "new-password")
            or any(k in hint for k in ("password", "passwd", "pwd", "passcode", "passphrase"))
        )

        if is_password_field:
            # Mark the DOM element bounding box so the screenshot is masked
            conf = 0.99 if typ == "password" else 0.95
            findings.append(Finding("PASSWORD", el_loc, "dom", conf))

            # If a password value is present (even if exposed as type="text" via show-password),
            # register it as a value_text finding so the sanitizer redacts it across all text
            if val_str and len(val_str) >= 1:
                findings.append(Finding("PASSWORD", {"value_text": val_str}, "dom", 0.99))

            # If innerText contains exposed password characters
            if txt and any(k in hint for k in ("password", "passwd", "pwd")) and len(txt) >= 4:
                # If text looks like a value rather than a label
                if not any(txt.strip() == w for w in ("password", "show password", "hide password", "enter password")):
                    findings.append(Finding("PASSWORD", {"value_text": str(el.get("text")).strip()}, "dom", 0.90))

        # -------------------------------------------------------------
        # SENSITIVE AUTOCOMPLETE (Cards & OTPs)
        # -------------------------------------------------------------
        elif ac in SENSITIVE_AUTOCOMPLETE:
            cat = "CARD" if "cc" in ac else ("OTP" if ac == "one-time-code" else "PASSWORD")
            findings.append(Finding(cat, el_loc, "dom", 0.95))
            if val_str and len(val_str) >= 1:
                findings.append(Finding(cat, {"value_text": val_str}, "dom", 0.95))

        # -------------------------------------------------------------
        # OTHER SENSITIVE FIELDS BY HINTS
        # -------------------------------------------------------------
        elif any(k in hint for k in ("otp", "one-time", "verification", "auth-code")):
            findings.append(Finding("OTP", el_loc, "dom", 0.85))
            if val_str and len(val_str) >= 1:
                findings.append(Finding("OTP", {"value_text": val_str}, "dom", 0.90))
        elif any(k in hint for k in ("card", "cc-number", "credit", "debit", "cardnumber", "cvv", "cvc")):
            findings.append(Finding("CARD", el_loc, "dom", 0.85))
            if val_str and len(val_str) >= 1:
                findings.append(Finding("CARD", {"value_text": val_str}, "dom", 0.95))
        elif any(k in hint for k in ("aadhaar", "uidai")):
            findings.append(Finding("AADHAAR", el_loc, "dom", 0.85))
            if val_str and len(val_str) >= 1:
                findings.append(Finding("AADHAAR", {"value_text": val_str}, "dom", 0.95))
        elif any(k in hint for k in ("pan", "pan-card", "pancard")):
            findings.append(Finding("PAN", el_loc, "dom", 0.85))
            if val_str and len(val_str) >= 1:
                findings.append(Finding("PAN", {"value_text": val_str}, "dom", 0.95))
        elif any(k in hint for k in ("api_key", "api-key", "apikey", "secret_key", "token", "secret")):
            findings.append(Finding("API_KEY", el_loc, "dom", 0.85))
            if val_str and len(val_str) >= 1:
                findings.append(Finding("API_KEY", {"value_text": val_str}, "dom", 0.95))
        elif any(k in hint for k in ("ip", "ip_addr", "ip-address", "ipaddress")):
            findings.append(Finding("IP", el_loc, "dom", 0.85))
        elif any(k in hint for k in ("email", "mail")):
            findings.append(Finding("EMAIL", el_loc, "dom", 0.85))
        elif any(k in hint for k in ("phone", "mobile", "tel")):
            findings.append(Finding("PHONE", el_loc, "dom", 0.85))
        elif any(k in hint for k in ("address", "addr", "street")):
            findings.append(Finding("ADDRESS", el_loc, "dom", 0.85))
        elif any(k in hint for k in ("name", "fullname", "full-name")):
            findings.append(Finding("NAME", el_loc, "dom", 0.85))

        # Also inspect input values directly if present with regex scanners
        if val:
            for vf in scan_text(str(val)):
                findings.append(Finding(vf.category, el_loc, "dom", vf.confidence))

    return findings
