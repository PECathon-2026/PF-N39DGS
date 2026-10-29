"""Egress security gateway and inspection chokepoint.

Enforces zero-leakage egress controls between agent reasoning components and
external network destinations. All outgoing requests must pass inspection:
- Host allowlisting
- Provider key confinement
- Multi-form normalization and sensitive entity detection
- Active Vault cross-checking
- Canary token detection
- Registered sanitized image verification
- Audit logging with zero raw secrets
- Fail-closed error handling
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import logging
import os
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from privacylens.config import EgressConfig, get_config
from privacylens.detect.text_api import detect_text
from privacylens.detect.vision import ocr_detect
from privacylens.gateway.audit import AuditLogger
from privacylens.vault import Vault

logger = logging.getLogger(__name__)

_CANARY_REGEX = re.compile(r"CANARY-[A-Za-z0-9_-]+", re.IGNORECASE)
_ZERO_WIDTH_REGEX = re.compile(r"[\u200b-\u200f\u2060\ufeff]")
_DIGIT_SEP_REGEX = re.compile(r"(?<=\d)[\s\-_]+(?=\d)")
_BASE64_TOKEN_REGEX = re.compile(r"[A-Za-z0-9+/]{4,}={0,2}")
_HEX_TOKEN_REGEX = re.compile(r"[0-9a-fA-F]{4,}")

# Known image magic headers
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_JPEG_MAGIC = b"\xff\xd8\xff"
_WEBP_MAGIC_RIFF = b"RIFF"
_WEBP_MAGIC_WEBP = b"WEBP"


@dataclass
class EgressRequest:
    """Outgoing network request representation for inspection."""

    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | str | None = None


@dataclass
class Decision:
    """Egress decision returned by the inspection gate."""

    allowed: bool
    reason: str
    violations: list[str] = field(default_factory=list)


class EgressBlocked(Exception):
    """Raised when an egress request is rejected by the gate.

    Contains rejection reason and safe violation codes, strictly never raw secrets.
    """

    def __init__(self, reason: str, violations: list[str] | None = None) -> None:
        self.reason = reason
        self.violations = violations or []
        msg = f"Egress blocked: {reason}"
        if self.violations:
            msg += f" (violations: {', '.join(self.violations)})"
        super().__init__(msg)


def normalize_text_variants(text: str) -> list[str]:
    """Generate normalized representations of input string for sensitive detection."""
    variants = [text]

    # 1. URL-decoded
    try:
        unquoted = urllib.parse.unquote(text)
        if unquoted != text:
            variants.append(unquoted)
    except Exception:
        pass

    # 2. HTML-unescaped
    try:
        unescaped = html.unescape(text)
        if unescaped != text:
            variants.append(unescaped)
    except Exception:
        pass

    # 3. Unicode NFKC
    nfkc = unicodedata.normalize("NFKC", text)
    if nfkc != text:
        variants.append(nfkc)

    # 4. Zero-width character stripped
    zw_stripped = _ZERO_WIDTH_REGEX.sub("", text)
    if zw_stripped != text:
        variants.append(zw_stripped)

    # 5. Digit separator collapsed (spaces/hyphens between digits)
    # Exclude standard ISO-8601 dates (e.g. 2026-10-29) from being collapsed into phone numbers
    text_no_dates = re.sub(r"\b\d{4}-\d{2}-\d{2}\b", " ", text)
    dig_collapsed = _DIGIT_SEP_REGEX.sub("", text_no_dates)
    if dig_collapsed != text:
        variants.append(dig_collapsed)

    # Combined zero-width + digit-separator
    zw_no_dates = re.sub(r"\b\d{4}-\d{2}-\d{2}\b", " ", zw_stripped)
    zw_dig = _DIGIT_SEP_REGEX.sub("", zw_no_dates)
    if zw_dig not in variants:
        variants.append(zw_dig)

    # 6. Base64 decoded tokens
    trimmed = text.strip()
    if len(trimmed) >= 4 and len(trimmed) % 4 == 0 and re.match(r"^[A-Za-z0-9+/]+={0,2}$", trimmed):
        try:
            dec = base64.b64decode(trimmed).decode("utf-8")
            if dec and all(32 <= ord(c) < 127 or c in "\r\n\t" for c in dec):
                variants.append(dec)
        except Exception:
            pass

    for match in re.finditer(r"[A-Za-z0-9+/]{4,}={0,2}", text):
        token = match.group()
        if len(token) % 4 == 0:
            try:
                decoded_bytes = base64.b64decode(token)
                decoded = decoded_bytes.decode("utf-8")
                if decoded and all(32 <= ord(c) < 127 or c in "\r\n\t" for c in decoded):
                    variants.append(decoded)
            except Exception:
                pass

    # 7. Hex decoded tokens
    trimmed_hex = text.strip()
    if (
        len(trimmed_hex) >= 4
        and len(trimmed_hex) % 2 == 0
        and re.match(r"^[0-9a-fA-F]+$", trimmed_hex)
    ):
        try:
            dec = bytes.fromhex(trimmed_hex).decode("utf-8")
            if dec and all(32 <= ord(c) < 127 or c in "\r\n\t" for c in dec):
                variants.append(dec)
        except Exception:
            pass

    for match in re.finditer(r"[0-9a-fA-F]{4,}", text):
        token = match.group()
        if len(token) % 2 == 0:
            try:
                decoded = bytes.fromhex(token).decode("utf-8")
                if decoded and all(32 <= ord(c) < 127 or c in "\r\n\t" for c in decoded):
                    variants.append(decoded)
            except Exception:
                pass

    return variants


def _is_image_bytes(data: bytes) -> bool:
    """Check if byte sequence contains known image format magic bytes."""
    if data.startswith(_PNG_MAGIC) or data.startswith(_JPEG_MAGIC):
        return True
    if len(data) >= 12 and data.startswith(_WEBP_MAGIC_RIFF) and data[8:12] == _WEBP_MAGIC_WEBP:
        return True
    return False


def _extract_payload_components(obj: Any) -> tuple[list[str], list[bytes]]:
    """Recursively extract text strings and raw image payloads from a decoded payload."""
    text_pieces: list[str] = []
    image_payloads: list[bytes] = []

    def _walk(item: Any, parent_key: str = "") -> None:
        if isinstance(item, str):
            # Check for data URL image
            if item.startswith("data:image/") and ";base64," in item:
                try:
                    _, b64data = item.split(";base64,", 1)
                    img_bytes = base64.b64decode(b64data)
                    image_payloads.append(img_bytes)
                except Exception:
                    pass
            text_pieces.append(item)
        elif isinstance(item, (int, float, bool)):
            text_pieces.append(str(item))
        elif isinstance(item, dict):
            # Check for Gemini inline_data style: {"mime_type": "image/...", "data": "<base64>"}
            mime = item.get("mime_type") or item.get("mimeType")
            data_val = item.get("data")
            if (
                mime
                and isinstance(mime, str)
                and mime.startswith("image/")
                and isinstance(data_val, str)
            ):
                try:
                    img_bytes = base64.b64decode(data_val)
                    image_payloads.append(img_bytes)
                except Exception:
                    pass
                # Do NOT walk into base64 image binary as text
                return

            for k, v in item.items():
                if isinstance(k, str):
                    text_pieces.append(k)
                _walk(v, parent_key=str(k))
        elif isinstance(item, (list, tuple, set)):
            for element in item:
                _walk(element, parent_key=parent_key)

    _walk(obj)
    return text_pieces, image_payloads


class EgressGate:
    """Single-chokepoint inspection and enforcement gate for all outgoing network traffic."""

    def __init__(
        self,
        config: EgressConfig | None = None,
        audit_logger: AuditLogger | None = None,
        vault: Vault | None = None,
    ) -> None:
        """Initialize egress gate.

        Args:
            config: Egress configuration settings (defaults to config.yaml).
            audit_logger: Audit logger for tamper-evident logging.
            vault: Active Vault instance for secret cross-checking.
        """
        if config is not None:
            self.config = config
        else:
            try:
                self.config = get_config().egress
            except Exception:
                self.config = EgressConfig()

        self.audit_logger = audit_logger or AuditLogger()
        self.vault = vault
        self._registered_image_hashes: set[str] = set()

    def register_sanitized_image(self, image_bytes: bytes) -> str:
        """Register a sanitized image hash with the gate.

        Returns:
            SHA-256 hex digest of registered image.
        """
        digest = hashlib.sha256(image_bytes).hexdigest()
        self._registered_image_hashes.add(digest)
        return digest

    def register_vault(self, vault: Vault) -> None:
        """Attach active surrogate tokenization vault for secret cross-checking."""
        self.vault = vault

    def inspect(self, request: EgressRequest) -> Decision:
        """Inspect request and produce an egress decision. Fail-closed on any error.

        Args:
            request: EgressRequest to evaluate.

        Returns:
            Decision object (allowed=True/False, reason, violations).
        """
        try:
            return self._do_inspect(request)
        except Exception as exc:
            logger.error("Unhandled exception in EgressGate inspection: %s", exc, exc_info=True)
            # Fail closed: reject request and log audit record
            violations = ["internal_inspection_error"]
            try:
                parsed = urllib.parse.urlparse(request.url)
                dest_host = parsed.hostname or "unknown"
                path = parsed.path or "/"
            except Exception:
                dest_host = "unknown"
                path = "/"

            self.audit_logger.log_egress_decision(
                dest_host=dest_host,
                path=path,
                method=request.method,
                decision="block",
                violations=violations,
            )
            return Decision(
                allowed=False,
                reason=f"Gate inspection error: {type(exc).__name__}",
                violations=violations,
            )

    def enforce(self, request: EgressRequest) -> None:
        """Inspect request and raise EgressBlocked if not allowed.

        Args:
            request: EgressRequest to evaluate.

        Raises:
            EgressBlocked: If request fails egress policy.
        """
        decision = self.inspect(request)
        if not decision.allowed:
            raise EgressBlocked(decision.reason, decision.violations)

    def _do_inspect(self, request: EgressRequest) -> Decision:
        """Internal inspection implementation."""
        violations: list[str] = []
        hash_prefixes: list[str] = []

        # 1. URL and Host Validation
        parsed_url = urllib.parse.urlparse(request.url)
        dest_host = (parsed_url.hostname or "").lower()
        path = parsed_url.path or "/"
        query = parsed_url.query or ""

        # Normalize allowed hosts (lowercased)
        allowed_hosts = {h.lower() for h in self.config.allowed_hosts}
        if dest_host not in allowed_hosts:
            violations.append(f"unauthorized_host:{dest_host}")

        # 2. Provider Key Confinement Check
        # Check GEMINI_API_KEY from environment or auth headers
        gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
        provider_keys: list[str] = []
        if gemini_key and len(gemini_key) >= 8:
            provider_keys.append(gemini_key)

        for h_k, h_v in request.headers.items():
            if h_k.lower() == "x-goog-api-key" and h_v and len(h_v) >= 8:
                if h_v not in provider_keys:
                    provider_keys.append(h_v)

        for p_key in provider_keys:
            # Must NOT appear in path
            if p_key in path:
                violations.append("provider_key_in_path")

            # In query params: only permitted for generativelanguage.googleapis.com
            if p_key in query:
                if "generativelanguage.googleapis.com" not in dest_host:
                    violations.append("provider_key_in_unauthorized_query")

            # In headers: only permitted in designated auth headers
            auth_header_names = {"x-goog-api-key", "authorization"}
            for h_name, h_val in request.headers.items():
                if h_name.lower() not in auth_header_names and p_key in h_val:
                    violations.append(f"provider_key_in_header:{h_name.lower()}")

        # 3. Extract Text and Images from Payload
        text_pieces: list[str] = [path]
        image_payloads: list[bytes] = []

        # Parse query params as text
        if query:
            for q_k, q_v in urllib.parse.parse_qsl(query, keep_blank_values=True):
                text_pieces.append(q_k)
                text_pieces.append(q_v)

        # Inspect headers (exclude standard transport and auth headers)
        transport_headers = {
            "host",
            "content-length",
            "content-type",
            "accept",
            "accept-encoding",
            "connection",
            "user-agent",
            "x-goog-api-key",
            "authorization",
        }
        for h_name, h_val in request.headers.items():
            if h_name.lower() not in transport_headers:
                text_pieces.append(h_name)
                text_pieces.append(h_val)

        # Inspect body
        if request.body:
            if isinstance(request.body, bytes):
                if _is_image_bytes(request.body):
                    image_payloads.append(request.body)
                else:
                    try:
                        decoded_body = request.body.decode("utf-8")
                        try:
                            json_obj = json.loads(decoded_body)
                            tp, ip = _extract_payload_components(json_obj)
                            text_pieces.extend(tp)
                            image_payloads.extend(ip)
                        except Exception:
                            text_pieces.append(decoded_body)
                    except UnicodeDecodeError:
                        # Raw binary body
                        pass
            elif isinstance(request.body, str):
                try:
                    json_obj = json.loads(request.body)
                    tp, ip = _extract_payload_components(json_obj)
                    text_pieces.extend(tp)
                    image_payloads.extend(ip)
                except Exception:
                    text_pieces.append(request.body)

        # Also check for provider keys in body
        for p_key in provider_keys:
            for tp in text_pieces:
                if p_key in tp:
                    violations.append("provider_key_in_body")
                    break

        # Combined string across all text fields (detects split tokens)
        combined_text = " ".join(text_pieces)
        all_texts_to_check = text_pieces + [combined_text]

        # Collect all texts and their normalized variants
        all_variants_to_check: list[str] = []
        for text in all_texts_to_check:
            if text:
                all_variants_to_check.extend(normalize_text_variants(text))
        all_variants_to_check = list(dict.fromkeys(all_variants_to_check))

        # 4. Canary Detection
        for text in all_variants_to_check:
            if _CANARY_REGEX.search(text):
                violations.append("canary_detected")
                break

        # 5. Sensitive Entity Detection with Multi-Form Normalization
        seen_entity_violations: set[str] = set()
        for variant in all_variants_to_check:
            if not variant or len(variant) < 3:
                continue

            findings = detect_text(variant)
            for f in findings:
                if f.type == "CARD_MASKED":
                    continue
                if f.type == "IP":
                    span_text = (
                        variant[f.start : f.end].strip()
                        if f.start is not None and f.end is not None
                        else ""
                    )
                    if span_text in {"127.0.0.1", "0.0.0.0", "::1"}:
                        continue
                v_type = f"sensitive_entity:{f.type}"
                if v_type not in seen_entity_violations:
                    seen_entity_violations.add(v_type)
                    violations.append(v_type)
                    hash_prefixes.append(AuditLogger.compute_hash_prefix(f.type))

        # 6. Active Vault Cross-Check
        if self.vault is not None:
            active_secrets = self.vault.get_active_secrets()
            for entity_type, raw_val in active_secrets:
                if not raw_val or len(raw_val) < 3:
                    continue
                raw_lower = raw_val.lower()
                raw_stripped = (
                    _ZERO_WIDTH_REGEX.sub("", raw_lower)
                    .replace(" ", "")
                    .replace("-", "")
                )

                for text in all_variants_to_check:
                    text_lower = text.lower()
                    text_stripped = (
                        _ZERO_WIDTH_REGEX.sub("", text_lower)
                        .replace(" ", "")
                        .replace("-", "")
                    )
                    text_nfkc = unicodedata.normalize("NFKC", text_stripped)
                    if (
                        raw_lower in text_lower
                        or raw_stripped in text_stripped
                        or raw_stripped in text_nfkc
                    ):
                        v_key = f"vault_secret:{entity_type}"
                        if v_key not in seen_entity_violations:
                            seen_entity_violations.add(v_key)
                            violations.append(v_key)
                            hash_prefixes.append(AuditLogger.compute_hash_prefix(entity_type))

        # 7. Registered Image Verification
        for img_bytes in image_payloads:
            img_hash = hashlib.sha256(img_bytes).hexdigest()
            if img_hash in self._registered_image_hashes:
                # Registered sanitized image, approved
                continue

            # Unrecognized image
            logger.warning("Unregistered image payload detected in egress request")
            if self.config.on_image_check_failure == "block":
                violations.append("unregistered_image_payload")

            # Scan image via OCR for sensitive text
            try:
                ocr_findings = ocr_detect(img_bytes)
                if ocr_findings:
                    violations.append("image_ocr_leak")
                    for of in ocr_findings:
                        hash_prefixes.append(AuditLogger.compute_hash_prefix(of.type))
            except Exception as ocr_err:
                logger.error("OCR scan failed on egress image: %s", ocr_err)
                violations.append("image_ocr_scan_failure")

        # Deduplicate violations while preserving order
        unique_violations = list(dict.fromkeys(violations))

        is_allowed = len(unique_violations) == 0
        reason = (
            "Egress payload verified clean"
            if is_allowed
            else "Policy violations detected in egress request"
        )
        decision = Decision(allowed=is_allowed, reason=reason, violations=unique_violations)

        # 8. Tamper-Evident Audit Logging
        self.audit_logger.log_egress_decision(
            dest_host=dest_host,
            path=path,
            method=request.method,
            decision="allow" if is_allowed else "block",
            violations=unique_violations,
            hash_prefixes=hash_prefixes[:10],
        )

        return decision
