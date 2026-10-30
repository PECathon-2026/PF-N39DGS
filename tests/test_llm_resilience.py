"""Tests for LLM provider resilience, key rotation, model fallback, and budget tracking."""

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from privacylens.agent.llm import GeminiProvider, RateLimitedError
from privacylens.events import EventBus
from privacylens.gateway.egress import EgressGate


class MockResilientTransport(httpx.BaseTransport):
    """Mock HTTP transport returning controlled responses to simulate 429 and success."""

    def __init__(self, responses: list[tuple[int, dict[str, Any]]]) -> None:
        super().__init__()
        self.responses = list(responses)
        self.recorded_requests: list[httpx.Request] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.recorded_requests.append(request)
        if self.responses:
            status_code, body = self.responses.pop(0)
        else:
            status_code, body = 200, {
                "candidates": [{"content": {"parts": [{"text": '{"action": "finish"}'}]}}]
            }
        return httpx.Response(
            status_code=status_code,
            json=body,
            request=request,
        )


def test_gemini_rotates_keys_on_429(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Verify GeminiProvider tries the next API key on 429."""
    monkeypatch.setenv("GEMINI_API_KEY", "primary-test-key")
    monkeypatch.setenv("GEMINI_API_KEY_2", "secondary-test-key")

    budget_file = tmp_path / "budget.json"
    gate = EgressGate(mode="audit_only")
    bus = EventBus(run_id="test_key_rotation")

    transport = MockResilientTransport(
        [
            (429, {"error": {"message": "Resource exhausted"}}),
            (200, {"candidates": [{"content": {"parts": [{"text": "success-from-key-2"}]}}]}),
        ]
    )

    provider = GeminiProvider(
        gate=gate,
        bus=bus,
        transport=transport,
    )
    provider.budget_file = budget_file
    provider.rpm_limit = 0  # disable throttle for fast unit test

    res = provider.complete("hello test")
    assert res == "success-from-key-2"

    # Verify 2 requests made with different keys
    assert len(transport.recorded_requests) == 2
    assert transport.recorded_requests[0].headers["x-goog-api-key"] == "primary-test-key"
    assert transport.recorded_requests[1].headers["x-goog-api-key"] == "secondary-test-key"

    # Verify event emitted with names only
    events = bus.get_events()
    fallback_events = [e for e in events if e.kind == "llm_fallback"]
    assert len(fallback_events) == 1
    assert fallback_events[0].data["from_key_env"] == "GEMINI_API_KEY"
    assert fallback_events[0].data["to_key_env"] == "GEMINI_API_KEY_2"


def test_gemini_falls_back_to_next_model(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Verify GeminiProvider falls back to next model when keys are exhausted."""
    monkeypatch.setenv("GEMINI_API_KEY", "only-one-key")
    monkeypatch.delenv("GEMINI_API_KEY_2", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY_3", raising=False)

    budget_file = tmp_path / "budget.json"
    gate = EgressGate(mode="audit_only")
    bus = EventBus(run_id="test_model_fallback")

    transport = MockResilientTransport(
        [
            (429, {"error": {"message": "Resource exhausted on flash"}}),
            (
                200,
                {"candidates": [{"content": {"parts": [{"text": "success-from-fallback-model"}]}}]},
            ),
        ]
    )

    provider = GeminiProvider(
        gate=gate,
        bus=bus,
        transport=transport,
    )
    provider.budget_file = budget_file
    provider.rpm_limit = 0

    res = provider.complete("hello model fallback")
    assert res == "success-from-fallback-model"

    assert len(transport.recorded_requests) == 2
    assert "gemini-3.5-flash" in str(transport.recorded_requests[0].url)
    assert "gemini-2.5-flash" in str(transport.recorded_requests[1].url)


def test_gemini_raises_ratelimited_error_when_exhausted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Verify provider stops cleanly with RateLimitedError when all options fail."""
    monkeypatch.setenv("GEMINI_API_KEY", "key-1")
    monkeypatch.delenv("GEMINI_API_KEY_2", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY_3", raising=False)

    budget_file = tmp_path / "budget.json"
    gate = EgressGate(mode="audit_only")

    # Return 429 for all model attempts
    transport = MockResilientTransport(
        [(429, {"error": {"message": "429"}})] * 20
    )

    provider = GeminiProvider(
        gate=gate,
        transport=transport,
    )
    provider.budget_file = budget_file
    provider.rpm_limit = 0

    with pytest.raises(RateLimitedError):
        provider.complete("doomed request")


def test_llm_budget_file_tracks_counts_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Verify logs/llm_budget.json stores counts only and never secret values."""
    monkeypatch.setenv("GEMINI_API_KEY", "sensitive-key-value-12345")
    budget_file = tmp_path / "llm_budget.json"

    gate = EgressGate(mode="audit_only")
    transport = MockResilientTransport(
        [(200, {"candidates": [{"content": {"parts": [{"text": "ok"}]}}]})]
    )

    provider = GeminiProvider(
        gate=gate,
        transport=transport,
    )
    provider.budget_file = budget_file
    provider.rpm_limit = 0

    provider.complete("test budget tracking")

    assert budget_file.exists()
    content = budget_file.read_text(encoding="utf-8")
    assert "sensitive-key-value-12345" not in content

    data = json.loads(content)
    assert data["total_calls"] == 1
    assert data["calls_by_model"]["gemini-3.5-flash"] == 1
