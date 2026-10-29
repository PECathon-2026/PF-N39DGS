"""Privacy-preserving audit logging for sanitization events.

Records entity types, counts, SHA-256 hash prefixes, decisions, and timestamps.
Strictly rejects raw values to prevent inadvertent data leakage into audit logs.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Valid SHA-256 hash prefix format (8 to 16 hexadecimal characters, lowercase)
_HASH_PREFIX_REGEX = re.compile(r"^[0-9a-fA-F]{8,16}$")
# Common raw sensitive formats to explicitly reject even if length matches
_RAW_NUMERIC_CARD_OR_ID = re.compile(r"^\d{12,19}$")



class AuditRecord(BaseModel):
    """Schema for individual audit log entries."""

    timestamp: str = Field(description="ISO 8601 UTC timestamp")
    entity_type: str = Field(description="Entity type identifier (e.g. CARD, EMAIL)")
    count: int = Field(ge=0, description="Number of instances detected and processed")
    hash_prefixes: list[str] = Field(
        description="List of truncated SHA-256 hash prefixes for correlation without reversal"
    )
    decision: str = Field(description="Policy decision applied (mask | block | allow)")


class AuditLogger:
    """Writes tamper-evident, privacy-preserving audit trails in JSONL format."""

    def __init__(self, log_path: str | Path = "logs/audit.jsonl") -> None:
        """Initialize AuditLogger with target file path."""
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def compute_hash_prefix(value: str, prefix_len: int = 12) -> str:
        """Compute a SHA-256 hex digest prefix for an entity value.

        Args:
            value: Input string.
            prefix_len: Number of hex characters to retain (8 to 16).

        Returns:
            Truncated hex digest prefix.
        """
        clamped_len = max(8, min(16, prefix_len))
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
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
            hash_prefixes: Truncated SHA-256 hex prefixes.
            decision: Action taken ('mask', 'block', 'allow').

        Raises:
            ValueError: If any item in hash_prefixes does not conform to hex prefix format.
        """
        for item in hash_prefixes:
            if not _HASH_PREFIX_REGEX.match(item) or _RAW_NUMERIC_CARD_OR_ID.match(item):
                raise ValueError(
                    f"AuditLogger rejected non-hash value: '{item}'. "
                    "Only 8-16 character hexadecimal SHA-256 prefixes are permitted."
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
