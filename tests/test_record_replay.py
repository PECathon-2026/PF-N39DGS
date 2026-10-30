"""Test suite for RecordingLLM, ReplayLLM, cassette safety, and Side Panel UI serving."""

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from privacylens.agent.llm import LLMProvider, RecordingLLM, ReplayLLM, SecurityError
from privacylens.api.app import app
from privacylens.api.auth import ACTIVE_TOKEN

client = TestClient(app)
AUTH_HEADERS = {"X-PL-Token": ACTIVE_TOKEN, "Host": "127.0.0.1:8000"}


class DummyProvider(LLMProvider):
    """Mock LLMProvider that returns pre-configured responses."""

    def __init__(self, responses: list[str]) -> None:
        self.responses = list(responses)
        self.model = "dummy-model"
        self._idx = 0

    def complete(self, prompt: str, image: bytes | None = None) -> str:
        if self._idx < len(self.responses):
            resp = self.responses[self._idx]
            self._idx += 1
            return resp
        return json.dumps({"action": {"action": "finish", "status": "success"}})


def test_recording_llm_normal_record(tmp_path: Path) -> None:
    """RecordingLLM records clean exchanges into cassette with prompt hash."""
    mock_resp = json.dumps(
        {"reason": "Clicking next", "action": {"action": "click", "element_id": "pl-btn"}}
    )
    provider = DummyProvider([mock_resp])
    recorder = RecordingLLM(provider=provider, scenario="test_checkout", cassette_dir=tmp_path)

    prompt = "Sanitized page state: [REDACTED:NAME] has item in cart. What next?"
    res = recorder.complete(prompt)

    assert res == mock_resp
    cassette_file = tmp_path / "test_checkout.json"
    assert cassette_file.exists()

    data = json.loads(cassette_file.read_text(encoding="utf-8"))
    assert data["scenario"] == "test_checkout"
    assert len(data["steps"]) == 1
    assert data["steps"][0]["step"] == 1
    assert len(data["steps"][0]["prompt_hash"]) == 64
    assert data["steps"][0]["response"] == mock_resp


def test_recording_llm_refuses_canary_in_prompt(tmp_path: Path) -> None:
    """RecordingLLM raises SecurityError if canary appears in outbound prompt."""
    provider = DummyProvider(["ok"])
    recorder = RecordingLLM(provider=provider, scenario="leak_prompt", cassette_dir=tmp_path)

    prompt = "Hello CANARY-998811 token leak!"
    with pytest.raises(SecurityError, match="canary token detected"):
        recorder.complete(prompt)

    cassette_file = tmp_path / "leak_prompt.json"
    assert not cassette_file.exists()


def test_recording_llm_refuses_canary_in_response(tmp_path: Path) -> None:
    """RecordingLLM raises SecurityError if canary appears in model response."""
    provider = DummyProvider(["I found token CANARY-443322!"])
    recorder = RecordingLLM(provider=provider, scenario="leak_resp", cassette_dir=tmp_path)

    prompt = "Normal sanitized prompt"
    with pytest.raises(SecurityError, match="canary token detected"):
        recorder.complete(prompt)

    cassette_file = tmp_path / "leak_resp.json"
    assert not cassette_file.exists()


def test_recording_llm_refuses_credit_card_in_prompt(tmp_path: Path) -> None:
    """RecordingLLM raises SecurityError if raw card number is found in prompt."""
    provider = DummyProvider(["ok"])
    recorder = RecordingLLM(provider=provider, scenario="leak_card", cassette_dir=tmp_path)

    prompt = "Payment info: 4111 1111 1111 1111"
    with pytest.raises(SecurityError, match="sensitive pattern detected"):
        recorder.complete(prompt)

    cassette_file = tmp_path / "leak_card.json"
    assert not cassette_file.exists()


def test_replay_llm_sequential_playback(tmp_path: Path) -> None:
    """ReplayLLM reads cassette and replays actions sequentially."""
    cassette_file = tmp_path / "replay_demo.json"
    step1 = json.dumps({"action": {"action": "click", "element_id": "pl-1"}})
    step2 = json.dumps({"action": {"action": "finish", "status": "success"}})
    cassette_data: dict[str, Any] = {
        "scenario": "replay_demo",
        "model": "gemini-3.5-flash",
        "steps": [
            {"step": 1, "prompt_hash": "abc", "response": step1},
            {"step": 2, "prompt_hash": "def", "response": step2},
        ],
    }
    cassette_file.write_text(json.dumps(cassette_data), encoding="utf-8")

    replayer = ReplayLLM(scenario="replay_demo", cassette_dir=tmp_path)
    res1 = replayer.complete("Prompt 1")
    assert json.loads(res1)["action"]["element_id"] == "pl-1"

    res2 = replayer.complete("Prompt 2")
    assert json.loads(res2)["action"]["action"] == "finish"

    # Step 3 is beyond recorded steps -> returns failure finish
    res3 = replayer.complete("Prompt 3")
    res3_obj = json.loads(res3)
    assert res3_obj["action"]["action"] == "finish"
    assert res3_obj["action"]["status"] == "failure"


def test_replay_llm_missing_cassette_raises(tmp_path: Path) -> None:
    """ReplayLLM raises FileNotFoundError if requested cassette does not exist."""
    with pytest.raises(FileNotFoundError, match="Cassette for scenario 'non_existent' not found"):
        ReplayLLM(scenario="non_existent", cassette_dir=tmp_path)


def test_sidepanel_ui_served_publicly() -> None:
    """GET /ui and static assets must return 200 without requiring X-PL-Token."""
    resp = client.get("/ui/", headers={"Host": "127.0.0.1:8000"})
    assert resp.status_code == 200
    assert "PrivacyLens" in resp.text

    resp_css = client.get("/ui/sidepanel.css", headers={"Host": "127.0.0.1:8000"})
    assert resp_css.status_code == 200
    assert "--bg-primary" in resp_css.text

    resp_js = client.get("/ui/sidepanel.js", headers={"Host": "127.0.0.1:8000"})
    assert resp_js.status_code == 200
    assert "updateConnectionStatus" in resp_js.text


def test_api_start_agent_run_replay(tmp_path: Path) -> None:
    """POST /v1/agent/runs accepts model='replay:<scenario>'."""
    # Create test cassette in eval/cassettes
    cassette_dir = Path("eval/cassettes")
    cassette_dir.mkdir(parents=True, exist_ok=True)
    cassette_file = cassette_dir / "unit_test_replay.json"
    finish_step = json.dumps({"action": {"action": "finish", "status": "success"}})
    cassette_file.write_text(
        json.dumps({
            "scenario": "unit_test_replay",
            "model": "gemini-test",
            "steps": [{"step": 1, "prompt_hash": "123", "response": finish_step}],
        }),
        encoding="utf-8",
    )

    try:
        resp = client.post(
            "/v1/agent/runs",
            json={
                "task": "Test replay scenario",
                "start_url": "http://127.0.0.1:8765/checkout.html",
                "model": "replay:unit_test_replay",
            },
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "run_id" in data
        assert data["status"] == "running"
    finally:
        if cassette_file.exists():
            cassette_file.unlink()
