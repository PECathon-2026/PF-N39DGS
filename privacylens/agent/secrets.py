"""Synthetic user secret store for PrivacyLens agent execution.

Provides an isolated local secret store for synthetic test credentials
(credit cards, CVVs, passwords, tokens). Never exposes secret values in
repr, str, or logging representations. Exposes only safe descriptive metadata.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict

logger = logging.getLogger(__name__)


def _normalize_ref(ref: str) -> str:
    """Normalize secret reference names by stripping outer brackets and prefixes."""
    s = ref.strip()
    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1].strip()
    if s.lower().startswith("secret:"):
        s = s[7:].strip()
    return s.lower()


class SecretMetadata(BaseModel):
    """Public, safe description of an available synthetic secret."""

    model_config = ConfigDict(extra="forbid")
    name: str
    type: str
    description: str
    placeholder: str


class SecretStore:
    """Secure local repository for synthetic secrets."""

    def __init__(self) -> None:
        """Initialize empty SecretStore."""
        self._entries: dict[str, dict[str, str]] = {}

    def register(
        self,
        name: str,
        value: str,
        entity_type: str = "SECRET",
        description: str = "",
    ) -> None:
        """Register a synthetic secret.

        Args:
            name: Identifier name (e.g. 'card_number').
            value: Secret payload value (never logged or exposed in metadata).
            entity_type: Entity classification (e.g. CARD, PASSWORD, CVV).
            description: Purpose description for agent reasoning.
        """
        key = _normalize_ref(name)
        self._entries[key] = {
            "name": name.strip(),
            "type": entity_type.upper().strip(),
            "value": str(value),
            "description": description.strip(),
        }

    def load_from_dict(self, data: dict[str, Any]) -> None:
        """Load secrets from a dictionary structure."""
        for name, info in data.items():
            if isinstance(info, dict):
                self.register(
                    name=name,
                    value=str(info.get("value", "")),
                    entity_type=str(info.get("type", "SECRET")),
                    description=str(info.get("description", "")),
                )
            elif isinstance(info, str):
                self.register(name=name, value=info)

    def load_yaml(self, path: str | Path) -> None:
        """Load secrets from a YAML configuration file."""
        cfg_path = Path(path)
        if not cfg_path.exists():
            raise FileNotFoundError(f"Secrets file not found: {cfg_path}")

        with open(cfg_path, encoding="utf-8") as f:
            content = yaml.safe_load(f)
            if isinstance(content, dict):
                # Handle possible top-level 'secrets:' wrapper key
                sec_dict = content.get("secrets", content)
                if isinstance(sec_dict, dict):
                    self.load_from_dict(sec_dict)

    def has_secret(self, ref: str) -> bool:
        """Check whether a secret exists by reference name or placeholder format."""
        key = _normalize_ref(ref)
        return key in self._entries

    def resolve(self, ref: str) -> str:
        """Resolve a secret reference strictly for local browser executor typing.

        Args:
            ref: Identifier name or placeholder (e.g. 'card_number' or '[SECRET:card_number]').

        Returns:
            The raw secret value.

        Raises:
            KeyError: If the referenced secret is not found.
        """
        key = _normalize_ref(ref)
        if key not in self._entries:
            raise KeyError(f"Secret reference '{ref}' not found in SecretStore")
        return self._entries[key]["value"]

    def get_descriptions(self) -> list[SecretMetadata]:
        """Return safe metadata descriptions of available secrets for prompt injection."""
        result: list[SecretMetadata] = []
        for key, entry in self._entries.items():
            result.append(
                SecretMetadata(
                    name=entry["name"],
                    type=entry["type"],
                    description=entry["description"],
                    placeholder=f"[SECRET:{entry['name']}]",
                )
            )
        return result

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, ref: str) -> bool:
        return self.has_secret(ref)

    def __repr__(self) -> str:
        names = [e["name"] for e in self._entries.values()]
        return f"SecretStore(count={len(self._entries)}, secrets={names})"

    def __str__(self) -> str:
        return self.__repr__()
