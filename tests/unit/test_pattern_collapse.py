"""Unit tests for deterministic pattern collapse helpers."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from autopack.pack.analysis import collapse_repeated_patterns
from autopack.schema import NormalizedEvent


def _event(*, event_id: str, offset_seconds: int, message: str) -> NormalizedEvent:
    base = datetime(2026, 4, 17, 10, 0, tzinfo=timezone.utc)
    return NormalizedEvent(
        event_id=event_id,
        timestamp=base + timedelta(seconds=offset_seconds),
        source_type="dlt",
        source_file="input.dlt",
        message=message,
        severity="error",
        category="reset",
        attributes={"line_number": offset_seconds + 1},
        tags=["dlt", "reset"],
        correlation_keys={"source_type": "dlt"},
    )


def test_collapse_repeated_patterns_groups_consecutive_events() -> None:
    events = [
        _event(event_id="evt-1", offset_seconds=0, message="ERROR modem reset 1001"),
        _event(event_id="evt-2", offset_seconds=2, message="ERROR modem reset 1002"),
        _event(event_id="evt-3", offset_seconds=4, message="ERROR modem reset 1003"),
        _event(event_id="evt-4", offset_seconds=20, message="ERROR modem reset 1004"),
    ]

    patterns = collapse_repeated_patterns(events, min_count=3, max_gap_seconds=5)

    assert len(patterns) == 1
    pattern = patterns[0]
    assert pattern["count"] == 3
    assert pattern["source_types"] == ["dlt"]
    assert pattern["categories"] == ["reset"]
    assert pattern["event_ids"] == ["evt-1", "evt-2", "evt-3"]
