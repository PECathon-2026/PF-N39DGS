from __future__ import annotations

import os
from typing import Any, Dict, List, Optional
from dotenv import load_dotenv

# In-memory dictionary storing sensitive vault values.
# Invariant: Never serialized to disk or exposed in logs.
_VAULT: Dict[str, str] = {}


def load_vault(env_path: Optional[str] = None) -> Dict[str, str]:
    """Populate the in-memory vault from .env and environment variables.
    
    Loads keys starting with VAULT_ or sensitive keywords.
    Never writes or serializes to disk.
    """
    global _VAULT
    if env_path and os.path.isfile(env_path):
        load_dotenv(env_path, override=False)
    else:
        load_dotenv(override=False)

    for k, v in os.environ.items():
        if not v or not isinstance(v, str):
            continue
        v_clean = v.strip()
        if not v_clean:
            continue
        if k.startswith("VAULT_"):
            sub_key = k[6:]
            _VAULT[k] = v_clean
            _VAULT[sub_key] = v_clean
        elif k in ("CARD_NUMBER", "PASSWORD", "AADHAAR", "PAN", "API_KEY", "USER_EMAIL"):
            _VAULT[k] = v_clean
            _VAULT[f"VAULT_{k}"] = v_clean

    return dict(_VAULT)


def get_vault() -> Dict[str, str]:
    """Return a copy of the in-memory vault."""
    return dict(_VAULT)


def set_secret(key: str, value: str) -> None:
    """Register a secret in the in-memory vault."""
    k_norm = key.strip()
    v_norm = value.strip()
    _VAULT[k_norm] = v_norm
    if not k_norm.startswith("VAULT_"):
        _VAULT[f"VAULT_{k_norm}"] = v_norm
    else:
        _VAULT[k_norm[6:]] = v_norm


def get_secret(key: str) -> Optional[str]:
    """Retrieve a secret by symbolic key name."""
    if key in _VAULT:
        return _VAULT[key]
    if f"VAULT_{key}" in _VAULT:
        return _VAULT[f"VAULT_{key}"]
    if key.startswith("VAULT_") and key[6:] in _VAULT:
        return _VAULT[key[6:]]
    return None


def is_vault_ref(value: Any) -> bool:
    """Check if a value is a symbolic vault reference (e.g. 'vault:CARD_NUMBER')."""
    return isinstance(value, str) and value.startswith("vault:")


def resolve_value(value: Any) -> Any:
    """Resolve a symbolic vault reference into its actual secret value locally.
    
    Invariant: Must only be invoked inside executor at execution time.
    """
    if not is_vault_ref(value):
        return value

    ref_key = value[len("vault:"):].strip()
    if ref_key.startswith("<") and ref_key.endswith(">"):
        ref_key = ref_key[1:-1].strip()

    secret = get_secret(ref_key)
    if secret is not None:
        return secret

    env_val = os.environ.get(ref_key) or os.environ.get(f"VAULT_{ref_key}")
    if env_val:
        return env_val.strip()

    return value


def all_values() -> List[str]:
    """Return all raw secret values stored in the vault."""
    return list(set(_VAULT.values()))


def all_symbolic_refs() -> List[str]:
    """Return all available symbolic reference keys as vault:KEY."""
    unique_keys = set()
    for k in _VAULT.keys():
        if not k.startswith("VAULT_"):
            unique_keys.add(f"vault:{k}")
    return sorted(unique_keys)


def clear_vault() -> None:
    """Clear all in-memory vault values."""
    _VAULT.clear()


# Initialize vault from environment on import
load_vault()

__all__ = [
    "load_vault",
    "get_vault",
    "set_secret",
    "get_secret",
    "is_vault_ref",
    "resolve_value",
    "all_values",
    "all_symbolic_refs",
    "clear_vault",
]
