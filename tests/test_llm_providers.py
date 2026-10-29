"""Unit tests for Gated LLM providers ensuring mandatory EgressGate chokepoint."""

from __future__ import annotations

from pathlib import Path

import pytest

from privacylens.agent.llm import (
    GeminiProvider,
    OllamaProvider,
    get_llm_provider,
)
from privacylens.config import EgressConfig
from privacylens.gateway.audit import AuditLogger
from privacylens.gateway.egress import EgressBlocked, EgressGate


def test_provider_requires_gate_at_instantiation() -> None:
    """Structural guarantee: Verify instantiating without an EgressGate raises TypeError."""
    # Attempting to instantiate GeminiProvider without gate
    with pytest.raises(TypeError, match="missing 1 required positional argument: 'gate'"):
        GeminiProvider()  # type: ignore[call-arg]

    # Attempting to pass None as gate
    with pytest.raises(TypeError, match="requires an initialized EgressGate instance"):
        GeminiProvider(gate=None)  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="requires an initialized EgressGate instance"):
        OllamaProvider(gate=None)  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="requires an initialized EgressGate instance"):
        get_llm_provider(gate=None)  # type: ignore[arg-type]


def test_gemini_provider_routes_through_gate(tmp_path: Path) -> None:
    """Verify GeminiProvider requests are inspected and blocked if gate rejects."""
    log_file = tmp_path / "logs" / "audit.jsonl"
    audit = AuditLogger(log_path=log_file)
    gate = EgressGate(
        config=EgressConfig(allowed_hosts=["generativelanguage.googleapis.com"]),
        audit_logger=audit,
    )

    provider = GeminiProvider(gate=gate, api_key="dummy-key-for-test")

    # If the prompt contains a canary token, the gate must intercept and block
    with pytest.raises(EgressBlocked, match="canary_detected"):
        provider.complete("Here is my secret CANARY-99887766 token")


def test_ollama_provider_graceful_offline(tmp_path: Path) -> None:
    """Verify OllamaProvider handles unreachable daemon without unhandled crash."""
    log_file = tmp_path / "logs" / "audit.jsonl"
    audit = AuditLogger(log_path=log_file)
    gate = EgressGate(
        config=EgressConfig(allowed_hosts=["127.0.0.1", "localhost"]),
        audit_logger=audit,
    )

    provider = OllamaProvider(gate=gate, host="http://127.0.0.1:59999")
    # Port 59999 is closed, should report unavailable
    res = provider.complete("Test prompt")
    assert "Ollama unavailable" in res
