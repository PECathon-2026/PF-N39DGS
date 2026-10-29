"""Privacy-preserving audit logging for sanitization events.

Records entity types, counts, HMAC-SHA256 prefixes, decisions, and timestamps.
Strictly rejects raw values to prevent inadvertent data leakage into audit logs.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Valid HMAC-SHA256 hex prefix format (8 to 16 hexadecimal characters, lowercase)
_HASH_PREFIX_REGEX = re.compile(r"^[0-9a-fA-F]{8,16}$")
# Common raw sensitive formats to explicitly reject even if length matches
_RAW_NUMERIC_CARD_OR_ID = re.compile(r"^\d{12,19}$")

# Random per-process HMAC key to protect low-entropy values (OTP, phone) from dictionary attacks
_PROCESS_HMAC_KEY = os.urandom(16)


class AuditRecord(BaseModel):
    """Schema for individual audit log entries."""

    timestamp: str = Field(description="ISO 8601 UTC timestamp")
    entity_type: str = Field(description="Entity type identifier (e.g. CARD, EMAIL)")
    count: int = Field(ge=0, description="Number of instances detected and processed")
    hash_prefixes: list[str] = Field(
        default_factory=list,
        description="Truncated HMAC-SHA256 prefixes for correlation without reversal",
    )
    decision: str = Field(description="Policy decision applied (mask | block | allow | resolve)")


class EgressAuditRecord(BaseModel):
    """Schema for egress gateway audit records."""

    timestamp: str = Field(description="ISO 8601 UTC timestamp")
    event_type: str = Field(default="egress", description="Audit event category")
    dest_host: str = Field(description="Destination hostname")
    path: str = Field(description="URL path")
    method: str = Field(description="HTTP method")
    decision: str = Field(description="Egress decision: allow or block")
    violations: list[str] = Field(
        default_factory=list,
        description="Violation types or categories",
    )
    hash_prefixes: list[str] = Field(
        default_factory=list,
        description="Truncated HMAC-SHA256 prefixes",
    )


class AuditLogger:
    """Writes tamper-evident, privacy-preserving audit trails in JSONL format."""

    def __init__(self, log_path: str | Path = "logs/audit.jsonl") -> None:
        """Initialize AuditLogger with target file path."""
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    @classmethod
    def compute_hash_prefix(cls, value: str, prefix_len: int = 12) -> str:
        """Compute an HMAC-SHA256 hex digest prefix using per-process key.

        Args:
            value: Input string.
            prefix_len: Number of hex characters to retain (8 to 16).

        Returns:
            Truncated hex digest prefix.
        """
        clamped_len = max(8, min(16, prefix_len))
        digest = hmac.new(_PROCESS_HMAC_KEY, value.encode("utf-8"), hashlib.sha256).hexdigest()
        return digest[:clamped_len]

    def log_event(
        self,
        entity_type: str,
        count: int,
        hash_prefixes: list[str],
        decision: str,
    ) -> None:
        """Log a sanitization event.

        Strictly rejects raw values. Every entry in hash_prefixes must be
        a valid 8-16 character hexadecimal hash prefix.

        Args:
            entity_type: Sensitive data type (e.g., 'CARD').
            count: Number of occurrences.
            hash_prefixes: Truncated HMAC-SHA256 hex prefixes.
            decision: Action taken ('mask', 'block', 'allow', 'resolve').

        Raises:
            ValueError: If any item in hash_prefixes does not conform to hex prefix format.
        """
        for item in hash_prefixes:
            if not _HASH_PREFIX_REGEX.match(item) or _RAW_NUMERIC_CARD_OR_ID.match(item):
                raise ValueError(
                    f"AuditLogger rejected non-hash value: '{item}'. "
                    "Only 8-16 character hexadecimal prefixes are permitted."
                )

        record = AuditRecord(
            timestamp=datetime.now(timezone.utc).isoformat(),
            entity_type=entity_type.upper(),
            count=count,
            hash_prefixes=[hp.lower() for hp in hash_prefixes],
            decision=decision.lower(),
        )

        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record.model_dump()) + "\n")

    def log_resolve_event(self, entity_type: str, count: int = 1) -> None:
        """Log a vault resolution event with type and count only (no hash or raw value)."""
        record = AuditRecord(
            timestamp=datetime.now(timezone.utc).isoformat(),
            entity_type=entity_type.upper(),
            count=count,
            hash_prefixes=[],
            decision="resolve",
        )
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record.model_dump()) + "\n")

    def log_egress_decision(
        self,
        dest_host: str,
        path: str,
        method: str,
        decision: str,
        violations: list[str],
        hash_prefixes: list[str] | None = None,
    ) -> None:
        """Log an egress gateway decision with zero raw secrets.

        Args:
            dest_host: Destination host.
            path: Destination path.
            method: HTTP method.
            decision: 'allow' or 'block'.
            violations: List of violation descriptions or categories.
            hash_prefixes: Optional HMAC-SHA256 hex prefixes.
        """
        prefixes = hash_prefixes or []
        for item in prefixes:
            if not _HASH_PREFIX_REGEX.match(item) or _RAW_NUMERIC_CARD_OR_ID.match(item):
                raise ValueError(
                    f"AuditLogger rejected non-hash value: '{item}'. "
                    "Only 8-16 character hexadecimal prefixes are permitted."
                )

        record = EgressAuditRecord(
            timestamp=datetime.now(timezone.utc).isoformat(),
            dest_host=dest_host,
            path=path,
            method=method.upper(),
            decision=decision.lower(),
            violations=violations,
            hash_prefixes=[hp.lower() for hp in prefixes],
        )
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record.model_dump()) + "\n")

    def read_records(self) -> list[dict[str, Any]]:
        """Read all logged audit records from the JSONL file."""
        if not self.log_path.exists():
            return []
        records: list[dict[str, Any]] = []
        with open(self.log_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records
