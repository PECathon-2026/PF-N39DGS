"""In-memory surrogate tokenization vault for PrivacyLens.

Maintains an isolated, ephemeral in-memory lookup table mapping tokenized
placeholders (e.g. [REDACTED:CARD_1]) back to true values strictly on the
local client machine. Placeholders are sequence counters per entity type and
are never derived from the underlying secret values.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from privacylens.gateway.audit import AuditLogger

logger = logging.getLogger(__name__)


class Vault:
    """In-memory surrogate tokenization vault securing sensitive data."""

    def __init__(
        self,
        ttl_seconds: float | None = None,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        """Initialize empty vault.

        Args:
            ttl_seconds: Optional lifespan in seconds after which tokens expire.
            audit_logger: AuditLogger instance used to record resolution events.
        """
        self._ttl_seconds = ttl_seconds
        self._audit_logger = audit_logger or AuditLogger()
        self._counters: dict[str, int] = {}
        self._raw_to_token: dict[tuple[str, str], str] = {}
        self._token_to_entry: dict[str, tuple[str, str, float]] = {}

    def put(self, entity_type: str, raw_value: str) -> str:
        """Store a raw sensitive value and return an opaque surrogate placeholder.

        The placeholder format is [REDACTED:{TYPE}_{COUNTER}] (e.g. [REDACTED:CARD_1]).
        Identical raw values of the same entity type reuse the same placeholder.

        Args:
            entity_type: Entity type identifier (e.g. CARD, EMAIL, AADHAAR).
            raw_value: True secret to be secured locally.

        Returns:
            Opaque placeholder string.
        """
        t = entity_type.upper().strip()
        now = time.time()

        key = (raw_value, t)
        if key in self._raw_to_token:
            token = self._raw_to_token[key]
            # Check if expired
            if token in self._token_to_entry:
                _, _, created_at = self._token_to_entry[token]
                if self._ttl_seconds is None or (now - created_at <= self._ttl_seconds):
                    return token

        # Increment sequence counter for entity type
        count = self._counters.get(t, 0) + 1
        self._counters[t] = count

        placeholder = f"[REDACTED:{t}_{count}]"
        self._raw_to_token[key] = placeholder
        self._token_to_entry[placeholder] = (t, raw_value, now)
        return placeholder

    def resolve(self, placeholder: str) -> str | None:
        """Resolve an opaque surrogate placeholder back to its original raw secret.

        Every resolution writes an audit event containing only the entity type
        and count (never the raw value).

        Args:
            placeholder: The placeholder identifier (e.g. [REDACTED:CARD_1]).

        Returns:
            The raw string if found and valid; otherwise None.
        """
        entry = self._token_to_entry.get(placeholder)
        if not entry:
            return None

        entity_type, raw_value, created_at = entry
        now = time.time()
        if self._ttl_seconds is not None and (now - created_at > self._ttl_seconds):
            # Token expired
            self._token_to_entry.pop(placeholder, None)
            key = (raw_value, entity_type)
            self._raw_to_token.pop(key, None)
            return None

        # Audit resolution event with entity type and count only
        try:
            self._audit_logger.log_resolve_event(entity_type=entity_type, count=1)
        except Exception:
            logger.warning("Failed to record vault resolve audit event", exc_info=True)

        return raw_value

    def has_placeholder(self, placeholder: str) -> bool:
        """Check whether a placeholder exists and is active in the vault."""
        if placeholder not in self._token_to_entry:
            return False
        if self._ttl_seconds is None:
            return True
        _, _, created_at = self._token_to_entry[placeholder]
        return (time.time() - created_at) <= self._ttl_seconds

    def get_active_secrets(self) -> list[tuple[str, str]]:
        """Return list of (entity_type, raw_value) for active non-expired tokens.

        Internal helper for egress cross-checking only.
        """
        now = time.time()
        active: list[tuple[str, str]] = []
        for _tok, (entity_type, raw_val, created_at) in self._token_to_entry.items():
            if self._ttl_seconds is None or (now - created_at <= self._ttl_seconds):
                active.append((entity_type, raw_val))
        return active

    def wipe(self) -> None:
        """Wipe all stored tokens and secrets from memory immediately."""
        self._counters.clear()
        self._raw_to_token.clear()
        self._token_to_entry.clear()

    def __len__(self) -> int:
        """Return the count of active tokens currently in the vault."""
        return len(self._token_to_entry)

    def __repr__(self) -> str:
        """Ensure vault representation NEVER exposes stored secrets."""
        return f"<Vault active_tokens={len(self._token_to_entry)}>"

    def __str__(self) -> str:
        """Ensure string conversion NEVER exposes stored secrets."""
        return f"<Vault active_tokens={len(self._token_to_entry)}>"

    def __reduce__(self) -> Any:
        """Prohibit pickling/serialization of in-memory vault secrets."""
        raise TypeError("Vault serialization is prohibited for security")

    def model_dump(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Prohibit dumping secrets through model serialization."""
        return {"active_tokens": len(self._token_to_entry)}


# Alias for backwards compatibility
LocalVault = Vault
