"""Security and safety unit tests for PrivacyLens privacy/utility baseline comparison."""

from __future__ import annotations

import pytest

from eval.run_baseline_eval import (
    SecurityOriginError,
    execute_baseline_comparison,
    validate_baseline_origin,
)
from privacylens.gateway.egress import EgressGate


def test_default_mode_strictly_enforces() -> None:
    """Verify that EgressGate default mode is strictly 'enforce'."""
    gate = EgressGate()
    assert gate.mode == "enforce"


def test_unsafe_baseline_rejects_external_hosts() -> None:
    """Verify that unsafe baseline strictly fails if target origin is not localhost."""
    with pytest.raises(SecurityOriginError, match="strictly restricted to localhost"):
        validate_baseline_origin("https://api.external-service.com/checkout")

    with pytest.raises(SecurityOriginError, match="strictly restricted to localhost"):
        validate_baseline_origin("http://192.168.1.50/login.html")

    # Localhost and 127.0.0.1 must succeed
    validate_baseline_origin("http://127.0.0.1:8765/checkout.html")
    validate_baseline_origin("http://localhost:8765/login.html")


def test_unsafe_baseline_fails_without_cli_flag() -> None:
    """Verify that baseline evaluation cannot execute without explicit --unsafe-baseline flag."""
    with pytest.raises(PermissionError, match="--unsafe-baseline"):
        execute_baseline_comparison(unsafe_baseline=False)


def test_unsafe_baseline_loud_warning_emitted(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify that loud security warning is printed when unsafe baseline is activated."""
    # Run with unsafe_baseline=True and mock on empty/minimal scenarios
    execute_baseline_comparison(unsafe_baseline=True, scenarios=[], mock=True)
    captured = capsys.readouterr()
    assert "CRITICAL SECURITY WARNING: UNSAFE BASELINE MODE ACTIVATED" in captured.out
