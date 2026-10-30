"""Event streaming and audit event bus for PrivacyLens agent execution.

Ensures real-time event distribution and persistent JSONL logging while
strictly preventing raw sensitive data or canaries from being written to logs.
"""

from __future__ import annotations

import collections
import logging
import re
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from privacylens.detect.text_api import detect_text

logger = logging.getLogger(__name__)

EventKind = Literal[
    "run_started",
    "sanitized",
    "gated",
    "proposed",
    "validated",
    "rejected",
    "approval_requested",
    "approved",
    "denied",
    "executed",
    "blocked",
    "injection_flagged",
    "llm_fallback",
    "finished",
    "error",
]

_CANARY_REGEX = re.compile(r"CANARY-[A-Za-z0-9_-]+", re.IGNORECASE)
_SAFE_REDACTED_STUB = "[REDACTED:SENSITIVE_EVENT_DATA]"


def _sanitize_data_payload(val: Any) -> Any:
    """Recursively inspect and redact any sensitive data or canary tokens."""
    if isinstance(val, str):
        # Check canaries
        if _CANARY_REGEX.search(val):
            return _SAFE_REDACTED_STUB
        # Check sensitive entities (ignore CARD_MASKED placeholders)
        findings = detect_text(val)
        active_findings = [f for f in findings if f.type != "CARD_MASKED"]
        if active_findings:
            return _SAFE_REDACTED_STUB
        return val
    elif isinstance(val, dict):
        return {k: _sanitize_data_payload(v) for k, v in val.items()}
    elif isinstance(val, list):
        return [_sanitize_data_payload(v) for v in val]
    return val


class Event(BaseModel):
    """Immutable, typed event record for agent execution streams."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str
    step: int = 0
    ts: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    kind: EventKind
    data: dict[str, Any] = Field(default_factory=dict)


class EventBus:
    """In-memory ring buffer and persistent JSONL sink for agent events."""

    def __init__(
        self,
        run_id: str,
        log_dir: str | Path = "logs/runs",
        buffer_size: int = 500,
    ) -> None:
        """Initialize EventBus for a specific agent execution run.

        Args:
            run_id: Unique identifier for the agent execution session.
            log_dir: Directory where run log JSONL files are stored.
            buffer_size: Maximum number of events to retain in ring buffer.
        """
        self.run_id = run_id
        self.log_dir = Path(log_dir)
        self.buffer_size = buffer_size
        self._buffer: collections.deque[Event] = collections.deque(maxlen=buffer_size)
        self._subscribers: list[Callable[[Event], Awaitable[None] | None]] = []

        # Ensure destination directory exists
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.sink_path = self.log_dir / f"{self.run_id}.jsonl"

    def subscribe(self, callback: Callable[[Event], Awaitable[None] | None]) -> None:
        """Register an event listener callback."""
        self._subscribers.append(callback)

    def emit(
        self,
        kind: EventKind,
        step: int = 0,
        data: dict[str, Any] | None = None,
    ) -> Event:
        """Construct, sanitize, log, and publish an event synchronously.

        Args:
            kind: Event category name.
            step: Current execution step index.
            data: Arbitrary payload attributes.

        Returns:
            The sanitized Event instance that was published.
        """
        raw_data = data or {}
        clean_data = _sanitize_data_payload(raw_data)
        event = Event(
            run_id=self.run_id,
            step=step,
            kind=kind,
            data=clean_data,
        )

        self._record_and_dispatch(event)
        return event

    async def emit_async(
        self,
        kind: EventKind,
        step: int = 0,
        data: dict[str, Any] | None = None,
    ) -> Event:
        """Construct, sanitize, log, and publish an event asynchronously.

        Args:
            kind: Event category name.
            step: Current execution step index.
            data: Arbitrary payload attributes.

        Returns:
            The sanitized Event instance that was published.
        """
        raw_data = data or {}
        clean_data = _sanitize_data_payload(raw_data)
        event = Event(
            run_id=self.run_id,
            step=step,
            kind=kind,
            data=clean_data,
        )

        self._record(event)
        for sub in self._subscribers:
            try:
                res = sub(event)
                if hasattr(res, "__await__"):
                    await res  # type: ignore[misc]
            except Exception as exc:
                logger.error("Error in async event subscriber: %s", exc, exc_info=True)

        return event

    def _record(self, event: Event) -> None:
        """Store in ring buffer and append to JSONL sink file."""
        self._buffer.append(event)
        try:
            with open(self.sink_path, "a", encoding="utf-8") as f:
                f.write(event.model_dump_json() + "\n")
        except Exception as exc:
            logger.error("Failed to write event to sink %s: %s", self.sink_path, exc)

    def _record_and_dispatch(self, event: Event) -> None:
        """Record event and notify subscribers synchronously."""
        self._record(event)
        for sub in self._subscribers:
            try:
                res = sub(event)
                # If callback returned a coroutine from synchronous emit, handle cleanly
                if hasattr(res, "__await__"):
                    import asyncio

                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(res)  # type: ignore[arg-type]
                    except RuntimeError:
                        asyncio.run(res)  # type: ignore[arg-type]
            except Exception as exc:
                logger.error("Error in event subscriber: %s", exc, exc_info=True)

    def get_events(self) -> list[Event]:
        """Return shallow copy of all events currently in the ring buffer."""
        return list(self._buffer)
