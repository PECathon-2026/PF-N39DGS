"""Unit tests for Event streaming and EventBus sanitization."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from privacylens.events import Event, EventBus


def test_event_model_immutability_and_validation() -> None:
    """Test Event field validation and forbidden extra fields."""
    event = Event(run_id="run-1", step=1, kind="run_started", data={"task": "test"})
    assert event.run_id == "run-1"
    assert event.step == 1
    assert event.kind == "run_started"

    # Extra fields forbidden
    with pytest.raises(ValidationError):
        Event(run_id="run-1", kind="run_started", extra_field="bad")  # type: ignore[call-arg]

    # Invalid kind rejected
    with pytest.raises(ValidationError):
        Event(run_id="run-1", kind="invalid_kind")  # type: ignore[arg-type]


def test_event_bus_ring_buffer(tmp_path: Path) -> None:
    """Verify in-memory ring buffer limits to specified capacity."""
    bus = EventBus(run_id="test_run", log_dir=tmp_path, buffer_size=3)
    for i in range(5):
        bus.emit("sanitized", step=i, data={"idx": i})

    events = bus.get_events()
    assert len(events) == 3
    assert [e.step for e in events] == [2, 3, 4]


def test_event_bus_jsonl_persistence(tmp_path: Path) -> None:
    """Verify events are properly persisted to the JSONL sink file."""
    bus = EventBus(run_id="run_jsonl", log_dir=tmp_path)
    bus.emit("run_started", step=0, data={"task": "buy shoes"})
    bus.emit("finished", step=1, data={"status": "success"})

    sink = tmp_path / "run_jsonl.jsonl"
    assert sink.exists()
    lines = sink.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 2
    assert '"kind":"run_started"' in lines[0]
    assert '"kind":"finished"' in lines[1]


def test_event_bus_sensitive_data_sanitization(tmp_path: Path) -> None:
    """Verify that sensitive values and canaries are redacted from event data."""
    bus = EventBus(run_id="run_sanitize", log_dir=tmp_path)

    # Payload with Luhn-valid credit card and canary token
    raw_payload = {
        "user_email": "jane@example.com",
        "card": "4111111111111111",
        "nested": {
            "canary": "CANARY-99887766",
            "safe_value": "standard text",
        },
        "safe_list": ["ok", "fine"],
    }

    event = bus.emit("proposed", step=1, data=raw_payload)

    # Assert sensitive values are replaced with safe stub
    assert event.data["user_email"] == "[REDACTED:SENSITIVE_EVENT_DATA]"
    assert event.data["card"] == "[REDACTED:SENSITIVE_EVENT_DATA]"
    assert event.data["nested"]["canary"] == "[REDACTED:SENSITIVE_EVENT_DATA]"
    assert event.data["nested"]["safe_value"] == "standard text"
    assert event.data["safe_list"] == ["ok", "fine"]

    # Verify sink file also contains redacted data
    sink = tmp_path / "run_sanitize.jsonl"
    sink_text = sink.read_text(encoding="utf-8")
    assert "4111111111111111" not in sink_text
    assert "CANARY-99887766" not in sink_text
    assert "jane@example.com" not in sink_text


def test_event_bus_async_subscribers(tmp_path: Path) -> None:
    """Verify async subscriber dispatching."""
    import asyncio

    async def _test() -> None:
        bus = EventBus(run_id="run_async", log_dir=tmp_path)
        received: list[Event] = []

        async def on_event(e: Event) -> None:
            received.append(e)

        bus.subscribe(on_event)
        await bus.emit_async("executed", step=1, data={"action": "click"})

        assert len(received) == 1
        assert received[0].kind == "executed"
        assert received[0].data["action"] == "click"

    asyncio.run(_test())
