"""Unit tests for advanced deterministic correlation rules."""

from __future__ import annotations

from datetime import datetime
from datetime import timedelta
from datetime import timezone

from autopack.pack.analysis import extract_correlations
from autopack.schema import NormalizedEvent


def _event(
    *,
    event_id: str,
    offset_seconds: int,
    source_type: str,
    message: str,
    severity: str = "info",
    ecu: str | None = None,
    app_id: str | None = None,
    context_id: str | None = None,
    frame_id: str | None = None,
    attributes: dict[str, object] | None = None,
) -> NormalizedEvent:
    base = datetime(2026, 4, 17, 10, 0, tzinfo=timezone.utc)
    return NormalizedEvent(
        event_id=event_id,
        timestamp=base + timedelta(seconds=offset_seconds),
        source_type=source_type,
        source_file=f"{source_type}.log",
        ecu=ecu,
        app_id=app_id,
        context_id=context_id,
        frame_id=frame_id,
        message=message,
        severity=severity,
        category="generic",
        attributes=attributes or {"line_number": offset_seconds + 1},
        tags=[source_type],
        correlation_keys={"source_type": source_type},
    )


def test_event_count_and_value_count_rules() -> None:
    events = [
        _event(
            event_id="evt-1",
            offset_seconds=0,
            source_type="dlt",
            severity="error",
            message="timeout while connecting",
            ecu="TCU",
            app_id="MODEM",
            context_id="NET",
        ),
        _event(
            event_id="evt-2",
            offset_seconds=30,
            source_type="dlt",
            severity="error",
            message="disconnect failed",
            ecu="TCU",
            app_id="MODEM",
            context_id="NET",
        ),
        _event(
            event_id="evt-3",
            offset_seconds=60,
            source_type="dlt",
            severity="error",
            message="timeout occurred again",
            ecu="TCU",
            app_id="MODEM",
            context_id="NET",
        ),
        _event(
            event_id="evt-4",
            offset_seconds=90,
            source_type="bus_asc",
            severity="warning",
            message="bus jitter",
            frame_id="0x101",
        ),
        _event(
            event_id="evt-5",
            offset_seconds=100,
            source_type="bus_asc",
            severity="warning",
            message="bus jitter",
            frame_id="0x102",
        ),
        _event(
            event_id="evt-6",
            offset_seconds=110,
            source_type="bus_asc",
            severity="warning",
            message="bus jitter",
            frame_id="0x103",
        ),
    ]

    correlations = extract_correlations([], events)
    rules = {item.rule for item in correlations}

    assert "event_count_5m" in rules
    assert "value_count_frame_id_5m" in rules


def test_ordered_failure_recovery_and_test_link_rules() -> None:
    events = [
        _event(
            event_id="evt-a",
            offset_seconds=0,
            source_type="dlt",
            severity="error",
            message="modem disconnect",
            ecu="TCU",
            app_id="MODEM",
            context_id="NET",
        ),
        _event(
            event_id="evt-b",
            offset_seconds=20,
            source_type="bus_blf",
            severity="error",
            message="bus timeout during reset",
            ecu="TCU",
            app_id="MODEM",
            context_id="NET",
        ),
        _event(
            event_id="evt-c",
            offset_seconds=40,
            source_type="syslog",
            severity="info",
            message="modem reconnect online",
            ecu="TCU",
            app_id="MODEM",
            context_id="NET",
        ),
        _event(
            event_id="evt-d",
            offset_seconds=80,
            source_type="test_pytest",
            severity="error",
            message="tests/test_mod.py::test_conn FAILED in 0.22s",
            attributes={"status": "failed", "test_id": "tests/test_mod.py::test_conn"},
        ),
    ]

    correlations = extract_correlations([], events)
    rules = {item.rule for item in correlations}

    assert "ordered_failure_reset_recover_10m" in rules
    assert "runtime_to_test_failure_10m" in rules
