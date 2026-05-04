"""Deterministic event analysis helpers for Phase 1 pack generation."""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from collections import defaultdict
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from pathlib import Path
from typing import Any
from typing import Sequence

from autopack.schema import Anomaly
from autopack.schema import Correlation
from autopack.schema import NormalizedEvent

_TIMESTAMP_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)
_NUMBER_RE = re.compile(r"\d+")


def extract_timestamp(line: str) -> datetime | None:
    """Extract a timestamp from a log line when possible."""
    match = _TIMESTAMP_RE.search(line)
    if not match:
        return None

    raw = match.group(1).replace(" ", "T")
    if raw.endswith("Z"):
        raw = raw.replace("Z", "+00:00")
    elif len(raw) >= 5 and raw[-3] != ":" and (raw[-5] in {"+", "-"}):
        raw = raw[:-2] + ":" + raw[-2:]

    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def classify_severity(message: str) -> str:
    """Classify event severity from message text."""
    lowered = message.lower()
    if any(token in lowered for token in ["fatal", "critical", "panic"]):
        return "critical"
    if any(
        token in lowered
        for token in ["error", "failed", "timeout", "disconnect", "reset", "exception"]
    ):
        return "error"
    if any(token in lowered for token in ["warn", "retry", "degraded"]):
        return "warning"
    return "info"


def classify_category(source_type: str, message: str) -> str:
    """Classify event category from source and message text."""
    lowered = message.lower()
    if "disconnect" in lowered or "reconnect" in lowered:
        return "connectivity"
    if "timeout" in lowered:
        return "timing"
    if "reset" in lowered:
        return "reset"
    if source_type.startswith("bus_"):
        return "bus"
    if source_type.startswith("test_"):
        return "test"
    if source_type == "syslog":
        return "platform"
    return "generic"


def event_id(source_type: str, path: Path, line_number: int, message: str) -> str:
    """Generate a deterministic event ID."""
    digest = hashlib.sha256(
        f"{source_type}|{path}|{line_number}|{message}".encode("utf-8")
    ).hexdigest()
    return f"evt-{digest[:16]}"


def extract_anomalies(events: list[NormalizedEvent]) -> list[Anomaly]:
    """Group error/critical events into deterministic anomaly windows."""
    trigger_events = [event for event in events if event.severity in {"error", "critical"}]
    if not trigger_events:
        return []

    anomalies: list[Anomaly] = []
    current_signature: str | None = None
    current_events: list[NormalizedEvent] = []

    for event in trigger_events:
        signature = _event_signature(event)
        if not current_events:
            current_signature = signature
            current_events = [event]
            continue

        previous = current_events[-1]
        if signature == current_signature and (event.timestamp - previous.timestamp) <= timedelta(
            seconds=5
        ):
            current_events.append(event)
            continue

        anomalies.append(_create_anomaly_from_group(current_signature or "unknown", current_events))
        current_signature = signature
        current_events = [event]

    if current_events:
        anomalies.append(_create_anomaly_from_group(current_signature or "unknown", current_events))

    return anomalies


def extract_correlations(
    anomalies: list[Anomaly], events: Sequence[NormalizedEvent] | None = None
) -> list[Correlation]:
    """Correlate evidence across sources using deterministic rule families."""
    correlations: list[Correlation] = []

    correlations.extend(_temporal_overlap_correlations(anomalies))

    if events:
        sorted_events = sorted(events, key=lambda item: (item.timestamp, item.event_id))
        correlations.extend(_event_count_correlations(sorted_events))
        correlations.extend(_value_count_bus_correlations(sorted_events))
        correlations.extend(_ordered_failure_recovery_correlations(sorted_events))
        correlations.extend(_test_linked_incident_correlations(sorted_events))

    return _deduplicate_correlations(correlations)


def _temporal_overlap_correlations(anomalies: list[Anomaly]) -> list[Correlation]:
    if len(anomalies) < 2:
        return []

    sorted_anomalies = sorted(anomalies, key=lambda item: (item.start_time, item.anomaly_id))
    correlations: list[Correlation] = []

    for index, left in enumerate(sorted_anomalies):
        for right in sorted_anomalies[index + 1 :]:
            window_gap = right.start_time - left.end_time
            if window_gap > timedelta(seconds=5):
                break

            left_sources = set(left.attributes.get("source_types", []))
            right_sources = set(right.attributes.get("source_types", []))
            if left_sources == right_sources:
                continue

            confidence = 0.6
            if left.kind == right.kind:
                confidence += 0.1
            if left.severity == "critical" or right.severity == "critical":
                confidence += 0.1

            event_ids = left.event_ids + right.event_ids
            source_types = sorted(left_sources | right_sources)

            correlations.append(
                _create_correlation(
                    rule="temporal_overlap_5s",
                    confidence=confidence,
                    window_start=min(left.start_time, right.start_time),
                    window_end=max(left.end_time, right.end_time),
                    event_ids=event_ids,
                    source_types=source_types,
                    summary=(
                        f"Anomalies {left.anomaly_id} and {right.anomaly_id} overlap within 5s "
                        f"across {', '.join(source_types)}"
                    ),
                    attributes={
                        "left_anomaly_id": left.anomaly_id,
                        "right_anomaly_id": right.anomaly_id,
                    },
                )
            )

    return correlations


def _event_count_correlations(events: Sequence[NormalizedEvent]) -> list[Correlation]:
    grouped: dict[tuple[str, str, str, str], list[NormalizedEvent]] = defaultdict(list)
    for event in events:
        if event.severity not in {"error", "critical"}:
            continue
        if not _contains_any(event.message, ["timeout", "disconnect", "failed", "error"]):
            continue

        key = (
            event.source_type,
            event.ecu or "",
            event.app_id or "",
            event.context_id or "",
        )
        grouped[key].append(event)

    correlations: list[Correlation] = []
    for key, group in grouped.items():
        if len(group) < 3:
            continue

        group_sorted = sorted(group, key=lambda item: (item.timestamp, item.event_id))
        left = 0
        emitted = False
        for right, item in enumerate(group_sorted):
            while item.timestamp - group_sorted[left].timestamp > timedelta(minutes=5):
                left += 1

            window = group_sorted[left : right + 1]
            if len(window) >= 3:
                source_type, ecu, app_id, context_id = key
                correlations.append(
                    _create_correlation(
                        rule="event_count_5m",
                        confidence=min(0.55 + (0.05 * len(window)), 0.9),
                        window_start=window[0].timestamp,
                        window_end=window[-1].timestamp,
                        event_ids=[event.event_id for event in window],
                        source_types=sorted({event.source_type for event in window}),
                        summary=(
                            f"{len(window)} failure events in 5m for "
                            f"source={source_type} ecu={ecu or '-'} app={app_id or '-'} ctx={context_id or '-'}"
                        ),
                        attributes={
                            "group_key": {
                                "source_type": source_type,
                                "ecu": ecu,
                                "app_id": app_id,
                                "context_id": context_id,
                            },
                            "threshold": 3,
                            "window_event_count": len(window),
                        },
                    )
                )
                emitted = True
                break

        if emitted:
            continue

    return correlations


def _value_count_bus_correlations(events: Sequence[NormalizedEvent]) -> list[Correlation]:
    grouped: dict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)
    for event in events:
        if event.source_type not in {"bus_blf", "bus_asc"}:
            continue

        key = (event.source_file, event.bus_channel or "")
        grouped[key].append(event)

    correlations: list[Correlation] = []
    for (source_file, bus_channel), group in grouped.items():
        if len(group) < 3:
            continue

        group_sorted = sorted(group, key=lambda item: (item.timestamp, item.event_id))
        left = 0
        for right, item in enumerate(group_sorted):
            while item.timestamp - group_sorted[left].timestamp > timedelta(minutes=5):
                left += 1

            window = group_sorted[left : right + 1]
            unique_frames = {event.frame_id for event in window if event.frame_id}
            if len(window) >= 3 and len(unique_frames) >= 3:
                correlations.append(
                    _create_correlation(
                        rule="value_count_frame_id_5m",
                        confidence=min(0.6 + (0.04 * len(unique_frames)), 0.9),
                        window_start=window[0].timestamp,
                        window_end=window[-1].timestamp,
                        event_ids=[event.event_id for event in window],
                        source_types=sorted({event.source_type for event in window}),
                        summary=(
                            f"{len(unique_frames)} unique bus frame IDs in 5m "
                            f"for {source_file} channel={bus_channel or '-'}"
                        ),
                        attributes={
                            "source_file": source_file,
                            "bus_channel": bus_channel,
                            "threshold_unique_frames": 3,
                            "unique_frame_count": len(unique_frames),
                        },
                    )
                )
                break

    return correlations


def _ordered_failure_recovery_correlations(events: Sequence[NormalizedEvent]) -> list[Correlation]:
    correlations: list[Correlation] = []
    for index, first in enumerate(events):
        if not _is_failure_event(first):
            continue

        for second in events[index + 1 :]:
            if second.timestamp - first.timestamp > timedelta(minutes=10):
                break
            if not _is_reset_or_timeout(second):
                continue
            if not _events_related(first, second):
                continue

            for third in events[index + 1 :]:
                if third.timestamp < second.timestamp:
                    continue
                if third.timestamp - first.timestamp > timedelta(minutes=10):
                    break
                if not _is_recovery_event(third):
                    continue
                if not (_events_related(first, third) or _events_related(second, third)):
                    continue

                triplet = [first, second, third]
                correlations.append(
                    _create_correlation(
                        rule="ordered_failure_reset_recover_10m",
                        confidence=0.78,
                        window_start=first.timestamp,
                        window_end=third.timestamp,
                        event_ids=[event.event_id for event in triplet],
                        source_types=sorted({event.source_type for event in triplet}),
                        summary=(
                            "Ordered failure→reset/timeout→recovery chain detected "
                            f"within 10m ({first.source_type},{second.source_type},{third.source_type})"
                        ),
                        attributes={
                            "ordered": True,
                            "sequence": ["failure", "reset_or_timeout", "recovery"],
                        },
                    )
                )
                break

            if correlations and correlations[-1].event_ids[0] == first.event_id:
                break

    return correlations


def _test_linked_incident_correlations(events: Sequence[NormalizedEvent]) -> list[Correlation]:
    runtime_events = [
        event
        for event in events
        if not event.source_type.startswith("test_") and event.severity in {"error", "critical"}
    ]
    test_failure_events = [
        event
        for event in events
        if event.source_type.startswith("test_") and _test_status(event) in {"failed", "error"}
    ]

    correlations: list[Correlation] = []
    for runtime_event in runtime_events:
        for test_event in test_failure_events:
            if test_event.timestamp < runtime_event.timestamp:
                continue
            if test_event.timestamp - runtime_event.timestamp > timedelta(minutes=10):
                break

            correlations.append(
                _create_correlation(
                    rule="runtime_to_test_failure_10m",
                    confidence=0.72,
                    window_start=runtime_event.timestamp,
                    window_end=test_event.timestamp,
                    event_ids=[runtime_event.event_id, test_event.event_id],
                    source_types=sorted({runtime_event.source_type, test_event.source_type}),
                    summary=(
                        "Runtime failure linked to test failure within 10m "
                        f"(test_id={test_event.attributes.get('test_id', '-')})"
                    ),
                    attributes={
                        "test_id": str(test_event.attributes.get("test_id", "")),
                        "status": _test_status(test_event),
                    },
                )
            )
            break

    return correlations


def _create_correlation(
    *,
    rule: str,
    confidence: float,
    window_start: datetime,
    window_end: datetime,
    event_ids: list[str],
    source_types: list[str],
    summary: str,
    attributes: dict[str, Any],
) -> Correlation:
    digest = hashlib.sha256(
        f"{rule}|{window_start.isoformat()}|{window_end.isoformat()}|{'|'.join(event_ids)}".encode(
            "utf-8"
        )
    ).hexdigest()

    return Correlation(
        correlation_id=f"cor-{digest[:16]}",
        rule=rule,
        confidence=max(0.0, min(confidence, 1.0)),
        window_start=window_start,
        window_end=window_end,
        event_ids=event_ids,
        source_types=source_types,
        summary=summary,
        attributes=attributes,
    )


def _deduplicate_correlations(correlations: Sequence[Correlation]) -> list[Correlation]:
    unique: list[Correlation] = []
    seen: set[tuple[str, tuple[str, ...], datetime, datetime]] = set()
    for correlation in correlations:
        key = (
            correlation.rule,
            tuple(correlation.event_ids),
            correlation.window_start,
            correlation.window_end,
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(correlation)
    return unique


def _contains_any(message: str, terms: list[str]) -> bool:
    lowered = message.lower()
    return any(term in lowered for term in terms)


def _is_failure_event(event: NormalizedEvent) -> bool:
    return event.severity in {"error", "critical"} or _contains_any(
        event.message,
        ["failed", "disconnect", "timeout", "error"],
    )


def _is_reset_or_timeout(event: NormalizedEvent) -> bool:
    return _contains_any(event.message, ["reset", "reboot", "restart", "timeout"])


def _is_recovery_event(event: NormalizedEvent) -> bool:
    return _contains_any(event.message, ["reconnect", "recovered", "online", "connected"])


def _events_related(left: NormalizedEvent, right: NormalizedEvent) -> bool:
    left_keys = {
        left.ecu or "",
        left.app_id or "",
        left.context_id or "",
        left.frame_id or "",
    }
    right_keys = {
        right.ecu or "",
        right.app_id or "",
        right.context_id or "",
        right.frame_id or "",
    }
    return bool({value for value in left_keys & right_keys if value})


def _test_status(event: NormalizedEvent) -> str:
    value = event.attributes.get("status")
    return str(value).lower() if value is not None else ""


def build_summary_markdown(
    events: list[NormalizedEvent],
    anomalies: list[Anomaly],
    correlations: list[Correlation],
) -> str:
    """Build concise deterministic summary markdown from analyzed evidence."""
    kind_counter = Counter(anomaly.kind for anomaly in anomalies)
    severity_counter = Counter(event.severity for event in events)

    top_kinds = (
        ", ".join(f"{kind}:{count}" for kind, count in kind_counter.most_common(5)) or "none"
    )
    severity_breakdown = (
        ", ".join(f"{severity}:{count}" for severity, count in severity_counter.most_common())
        or "none"
    )

    return "\n".join(
        [
            "# Incident Summary",
            "",
            "## Overview",
            f"- Total normalized events: **{len(events)}**",
            f"- Total anomalies: **{len(anomalies)}**",
            f"- Total correlations: **{len(correlations)}**",
            f"- Event severity breakdown: {severity_breakdown}",
            "",
            "## Top anomaly patterns",
            f"- {top_kinds}",
            "",
            "## Notes",
            "- Pack generated using deterministic preprocessing only (no LLM path).",
            "- Correlations are temporal and evidence-linked; inspect correlations.jsonl for details.",
            "",
        ]
    )


def _event_signature(event: NormalizedEvent) -> str:
    normalized_message = _NUMBER_RE.sub("<n>", event.message.lower())
    return f"{event.source_type}|{event.category}|{normalized_message}"


def _create_anomaly_from_group(signature: str, events: list[NormalizedEvent]) -> Anomaly:
    digest = hashlib.sha256(
        f"{signature}|{events[0].timestamp.isoformat()}|{events[-1].timestamp.isoformat()}".encode(
            "utf-8"
        )
    ).hexdigest()

    severity = "critical" if any(event.severity == "critical" for event in events) else "error"
    kind = "burst" if len(events) >= 3 else "event"

    source_types = sorted({event.source_type for event in events})
    categories = sorted({event.category for event in events})

    description = (
        f"{len(events)} {severity} event(s) detected for signature "
        f"{signature.split('|', maxsplit=2)[-1][:80]}"
    )

    return Anomaly(
        anomaly_id=f"an-{digest[:16]}",
        kind=kind,
        severity=severity,
        start_time=events[0].timestamp,
        end_time=events[-1].timestamp,
        event_ids=[event.event_id for event in events],
        evidence_sources=sorted({event.source_file for event in events}),
        description=description,
        score=min(1.0, 0.4 + (0.1 * len(events))),
        attributes={
            "source_types": source_types,
            "categories": categories,
            "event_count": len(events),
        },
    )
