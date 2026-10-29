"""Local tokenization vault for PrivacyLens.

Maintains an isolated, encrypted or ephemeral local lookup table mapping tokenized
placeholders (e.g., <CARD_1>) back to true values strictly on the local client machine,
ensuring raw secrets are never sent to external LLMs.
"""

from __future__ import annotations

import logging
import uuid

logger = logging.getLogger(__name__)


class LocalVault:
    """Ephemeral in-memory local surrogate token vault."""

    def __init__(self) -> None:
        """Initialize empty vault."""
        self._tokens: dict[str, str] = {}
        self._reverse_tokens: dict[str, str] = {}

    def store(self, entity_type: str, raw_value: str) -> str:
        """Store a raw sensitive value locally and return an opaque token placeholder.

        Args:
            entity_type: Category of entity (e.g. CARD, AADHAAR).
            raw_value: True secret to be secured locally.

        Returns:
            Opaque placeholder identifier string.
        """
        if raw_value in self._reverse_tokens:
            return self._reverse_tokens[raw_value]

        token_id = f"<{entity_type}_{uuid.uuid4().hex[:8]}>"
        self._tokens[token_id] = raw_value
        self._reverse_tokens[raw_value] = token_id
        return token_id

    def retrieve(self, token_id: str) -> str | None:
        """Retrieve original value for local substitution prior to DOM insertion."""
        return self._tokens.get(token_id)

    def clear(self) -> None:
        """Wipe all stored tokens from local memory."""
        self._tokens.clear()
        self._reverse_tokens.clear()

