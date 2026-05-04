"""Deterministic build pipeline for Phase 1 investigation packs."""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from autopack.pack.analysis import (
    build_summary_markdown,
    classify_category,
    classify_severity,
    collapse_repeated_patterns,
    event_id,
    extract_anomalies,
    extract_correlations,
    extract_timestamp,
)
from autopack.pack.writer import PackWriteResult, write_investigation_pack
from autopack.parsers.bus.adapter import parse_bus_trace
from autopack.parsers.dlt import parse_dlt_file
from autopack.parsers.syslog.adapter import parse_syslog_file
from autopack.parsers.testlogs.adapter import parse_test_log_file
from autopack.schema import Manifest, NormalizedEvent, SourceFileManifest

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class SourceInput:
    """Input source descriptor used during build."""

    source_type: str
    path: Path


@dataclass(slots=True)
class DltIngestRow:
    """Consolidated DLT ingest row with stable source provenance."""

    source_path: Path
    source_ordinal: int
    line_number: int
    message: str
    timestamp: datetime | None
    ecu: str | None
    app_id: str | None
    context_id: str | None


def build_pack_from_sources(
    *,
    dlt_paths: Sequence[Path] | None = None,
    dlt_path: Path | None = None,
    dlt_profile: str = "auto",
    dlt_vendor: str = "default",
    dbc_path: Path,
    output_dir: Path,
    blf_path: Path | None = None,
    asc_path: Path | None = None,
    syslog_path: Path | None = None,
    junit_path: Path | None = None,
    pytest_log_path: Path | None = None,
    artifacts_dir: Path | None = None,
    session_id: str | None = None,
) -> PackWriteResult:
    """Build an investigation pack from source files using deterministic preprocessing."""
    resolved_dlt_paths = _resolve_dlt_paths(dlt_paths=dlt_paths, dlt_path=dlt_path)

    sources = _resolve_sources(
        dlt_paths=resolved_dlt_paths,
        dbc_path=dbc_path,
        blf_path=blf_path,
        asc_path=asc_path,
        syslog_path=syslog_path,
        junit_path=junit_path,
        pytest_log_path=pytest_log_path,
        artifacts_dir=artifacts_dir,
    )

    events: list[NormalizedEvent] = []
    source_event_counts: dict[Path, int] = {source.path: 0 for source in sources}
    parse_warnings: list[str] = []

    synthetic_epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    synthetic_index = 0

    dlt_sources = [source for source in sources if source.source_type == "dlt"]
    if dlt_sources:
        dlt_rows: list[DltIngestRow] = []
        duplicate_count = 0
        seen_digests: set[str] = set()

        for source_ordinal, source in enumerate(dlt_sources):
            parsed_records, _backend, dlt_warnings = parse_dlt_file(
                source.path,
                profile=dlt_profile,
                vendor=dlt_vendor,
            )
            parse_warnings.extend(dlt_warnings)

            for record in parsed_records:
                dlt_rows.append(
                    DltIngestRow(
                        source_path=source.path,
                        source_ordinal=source_ordinal,
                        line_number=record.line_number,
                        message=record.parsed.message,
                        timestamp=record.parsed.timestamp,
                        ecu=record.parsed.ecu,
                        app_id=record.parsed.app_id,
                        context_id=record.parsed.context_id,
                    )
                )
                source_event_counts[source.path] += 1

        dlt_rows.sort(
            key=lambda row: (
                row.timestamp is None,
                row.timestamp or synthetic_epoch,
                str(row.source_path),
                row.line_number,
                row.source_ordinal,
            )
        )

        for row in dlt_rows:
            parsed_message = row.message

            timestamp = row.timestamp
            if timestamp is None:
                timestamp = synthetic_epoch + timedelta(milliseconds=synthetic_index)
            synthetic_index += 1

            canonical_digest = _canonical_digest(timestamp, parsed_message)
            if canonical_digest in seen_digests:
                duplicate_count += 1
            else:
                seen_digests.add(canonical_digest)

            category = classify_category("dlt", parsed_message)

            event = NormalizedEvent(
                event_id=event_id("dlt", row.source_path, row.line_number, parsed_message),
                timestamp=timestamp,
                source_type="dlt",
                source_file=str(row.source_path),
                ecu=row.ecu,
                app_id=row.app_id,
                context_id=row.context_id,
                message=parsed_message,
                severity=classify_severity(parsed_message),
                category=category,
                attributes={
                    "line_number": row.line_number,
                    "original_line_number": row.line_number,
                    "split_file_ordinal": row.source_ordinal,
                    "canonical_digest": canonical_digest,
                },
                tags=["dlt", category],
                correlation_keys={"source_type": "dlt"},
            )
            events.append(event)

        if duplicate_count > 0:
            parse_warnings.append(
                f"Duplicate DLT canonical digest entries detected: {duplicate_count}"
            )

    for source in sources:
        LOGGER.info("Processing source %s (%s)", source.path, source.source_type)

        # DBC is included in the manifest for provenance; decode stage lands in a later step.
        if source.source_type in {"dbc", "dlt"}:
            continue

        if source.source_type in {"bus_blf", "bus_asc"}:
            bus_frames, bus_warnings = parse_bus_trace(
                source.path,
                dbc_path=dbc_path,
            )
            parse_warnings.extend(bus_warnings)

            for frame in bus_frames:
                timestamp = frame.timestamp
                if timestamp is None:
                    timestamp = synthetic_epoch + timedelta(milliseconds=synthetic_index)
                synthetic_index += 1

                decoded_signal_names = sorted(frame.decoded_signals)
                primary_signal = decoded_signal_names[0] if decoded_signal_names else None
                category = classify_category(source.source_type, frame.message)

                event = NormalizedEvent(
                    event_id=event_id(
                        source.source_type,
                        source.path,
                        frame.line_number,
                        frame.message,
                    ),
                    timestamp=timestamp,
                    source_type=source.source_type,
                    source_file=str(source.path),
                    bus_channel=frame.channel,
                    frame_id=frame.frame_id,
                    signal_name=primary_signal,
                    message=frame.message,
                    severity=classify_severity(frame.message),
                    category=category,
                    attributes={
                        "line_number": frame.line_number,
                        "arbitration_id": frame.arbitration_id,
                        "data_hex": frame.data_hex,
                        "decoded_signals": frame.decoded_signals,
                    },
                    tags=[source.source_type, category],
                    correlation_keys={
                        "source_type": source.source_type,
                        "frame_id": frame.frame_id or "",
                    },
                )
                events.append(event)
                source_event_counts[source.path] += 1

            continue

        if source.source_type == "syslog":
            syslog_rows, syslog_warnings = parse_syslog_file(source.path)
            parse_warnings.extend(syslog_warnings)

            for syslog_row in syslog_rows:
                timestamp = syslog_row.timestamp
                if timestamp is None:
                    timestamp = synthetic_epoch + timedelta(milliseconds=synthetic_index)
                synthetic_index += 1

                category = classify_category(source.source_type, syslog_row.message)

                event = NormalizedEvent(
                    event_id=event_id(
                        source.source_type,
                        source.path,
                        syslog_row.line_number,
                        syslog_row.message,
                    ),
                    timestamp=timestamp,
                    source_type=source.source_type,
                    source_file=str(source.path),
                    ecu=syslog_row.hostname,
                    app_id=syslog_row.process,
                    context_id=syslog_row.pid,
                    message=syslog_row.message,
                    severity=classify_severity(syslog_row.message),
                    category=category,
                    attributes={
                        "line_number": syslog_row.line_number,
                        "hostname": syslog_row.hostname,
                        "process": syslog_row.process,
                        "pid": syslog_row.pid,
                    },
                    tags=[source.source_type, category],
                    correlation_keys={
                        "source_type": source.source_type,
                        "process": syslog_row.process or "",
                    },
                )
                events.append(event)
                source_event_counts[source.path] += 1

            continue

        if source.source_type in {"test_junit", "test_pytest"}:
            test_rows, test_warnings = parse_test_log_file(source.source_type, source.path)
            parse_warnings.extend(test_warnings)

            for test_row in test_rows:
                timestamp = test_row.timestamp
                if timestamp is None:
                    timestamp = synthetic_epoch + timedelta(milliseconds=synthetic_index)
                synthetic_index += 1

                category = classify_category(source.source_type, test_row.message)

                event = NormalizedEvent(
                    event_id=event_id(
                        source.source_type,
                        source.path,
                        test_row.line_number,
                        test_row.message,
                    ),
                    timestamp=timestamp,
                    source_type=source.source_type,
                    source_file=str(source.path),
                    app_id=test_row.framework,
                    context_id=test_row.test_id,
                    message=test_row.message,
                    severity=classify_severity(test_row.message),
                    category=category,
                    attributes={
                        "line_number": test_row.line_number,
                        "test_id": test_row.test_id,
                        "framework": test_row.framework,
                        "status": test_row.status,
                        "duration_seconds": test_row.duration_seconds,
                        "failure_kind": test_row.failure_kind,
                    },
                    tags=[source.source_type, category, test_row.status],
                    correlation_keys={
                        "source_type": source.source_type,
                        "test_id": test_row.test_id,
                        "status": test_row.status,
                    },
                )
                events.append(event)
                source_event_counts[source.path] += 1

            continue

        for line_number, raw_line in _iter_text_lines(source.path):
            normalized = raw_line.strip()
            if not normalized:
                continue

            timestamp = extract_timestamp(normalized)
            if timestamp is None:
                timestamp = synthetic_epoch + timedelta(milliseconds=synthetic_index)
            synthetic_index += 1

            event = NormalizedEvent(
                event_id=event_id(source.source_type, source.path, line_number, normalized),
                timestamp=timestamp,
                source_type=source.source_type,
                source_file=str(source.path),
                message=normalized,
                severity=classify_severity(normalized),
                category=classify_category(source.source_type, normalized),
                attributes={"line_number": line_number},
                tags=[source.source_type, classify_category(source.source_type, normalized)],
                correlation_keys={"source_type": source.source_type},
            )
            events.append(event)
            source_event_counts[source.path] += 1

    events.sort(key=_event_sort_key)

    pattern_collapses = collapse_repeated_patterns(events)
    anomalies = extract_anomalies(events)
    correlations = extract_correlations(anomalies, events)

    source_manifests = _build_source_manifests(
        sources=sources,
        source_event_counts=source_event_counts,
    )

    session = session_id or _deterministic_session_id(source_manifests)
    summary = build_summary_markdown(events, anomalies, correlations)

    manifest = Manifest(
        pack_version="1.0.0",
        session_id=session,
        created_at=datetime.now(timezone.utc),
        generator="autopack/0.1.0",
        source_files=source_manifests,
        total_events=len(events),
        total_anomalies=len(anomalies),
        total_correlations=len(correlations),
        parse_warnings=parse_warnings,
        notes=[
            "Phase 1 deterministic preprocessing pack",
            f"DLT parse profile: {dlt_profile}",
            f"DLT vendor mapping: {dlt_vendor}",
            "DBC file recorded for provenance; decode implementation follows in later build step",
        ],
    )

    source_artifacts = _build_source_artifacts(events=events, sources=sources)

    return write_investigation_pack(
        output_dir=output_dir,
        manifest=manifest,
        timeline=events,
        anomalies=anomalies,
        correlations=correlations,
        summary_markdown=summary,
        source_artifacts=source_artifacts,
        pattern_collapses=pattern_collapses,
    )


def _resolve_sources(
    *,
    dlt_paths: Sequence[Path],
    dbc_path: Path,
    blf_path: Path | None,
    asc_path: Path | None,
    syslog_path: Path | None,
    junit_path: Path | None,
    pytest_log_path: Path | None,
    artifacts_dir: Path | None,
) -> list[SourceInput]:
    if blf_path is None and asc_path is None:
        raise ValueError("Either --blf or --asc is required")

    if blf_path is not None and asc_path is not None:
        raise ValueError("Use either --blf or --asc, not both")

    source_inputs: list[SourceInput] = [
        *[SourceInput(source_type="dlt", path=path) for path in dlt_paths],
        SourceInput(source_type="dbc", path=dbc_path),
    ]

    if blf_path is not None:
        source_inputs.append(SourceInput(source_type="bus_blf", path=blf_path))
    if asc_path is not None:
        source_inputs.append(SourceInput(source_type="bus_asc", path=asc_path))
    if syslog_path is not None:
        source_inputs.append(SourceInput(source_type="syslog", path=syslog_path))
    if junit_path is not None:
        source_inputs.append(SourceInput(source_type="test_junit", path=junit_path))
    if pytest_log_path is not None:
        source_inputs.append(SourceInput(source_type="test_pytest", path=pytest_log_path))

    for source in source_inputs:
        if not source.path.exists():
            raise FileNotFoundError(
                f"Input file not found for --{source.source_type}: {source.path}"
            )
        if source.path.is_dir():
            raise ValueError(
                f"Expected file for --{source.source_type}, got directory: {source.path}"
            )

    if artifacts_dir is not None:
        if not artifacts_dir.exists():
            raise FileNotFoundError(f"Artifacts directory not found: {artifacts_dir}")
        if not artifacts_dir.is_dir():
            raise ValueError(f"--artifacts-dir must be a directory: {artifacts_dir}")

    return source_inputs


def _resolve_dlt_paths(*, dlt_paths: Sequence[Path] | None, dlt_path: Path | None) -> list[Path]:
    if dlt_paths is not None and dlt_path is not None:
        raise ValueError("Use either dlt_paths or dlt_path, not both")

    if dlt_paths is not None:
        resolved = [Path(path) for path in dlt_paths]
    elif dlt_path is not None:
        resolved = [dlt_path]
    else:
        raise ValueError("At least one DLT path is required")

    if not resolved:
        raise ValueError("At least one DLT path is required")

    return resolved


def _build_source_manifests(
    *, sources: Sequence[SourceInput], source_event_counts: dict[Path, int]
) -> list[SourceFileManifest]:
    dlt_sources = [source for source in sources if source.source_type == "dlt"]
    other_sources = [source for source in sources if source.source_type != "dlt"]

    source_manifests: list[SourceFileManifest] = []
    if len(dlt_sources) <= 1:
        for source in dlt_sources:
            source_manifests.append(
                SourceFileManifest(
                    source_type=source.source_type,
                    path=str(source.path),
                    sha256=_sha256_file(source.path),
                    size_bytes=source.path.stat().st_size,
                    event_count=source_event_counts[source.path],
                )
            )
    else:
        split_paths = [source.path for source in dlt_sources]
        split_hashes = [_sha256_file(path) for path in split_paths]
        split_payload = "|".join(
            f"{path}:{digest}"
            for path, digest in zip(split_paths, split_hashes, strict=True)
        )
        source_manifests.append(
            SourceFileManifest(
                source_type="dlt",
                path="dlt_consolidated",
                sha256=hashlib.sha256(split_payload.encode("utf-8")).hexdigest(),
                size_bytes=sum(path.stat().st_size for path in split_paths),
                event_count=sum(source_event_counts[path] for path in split_paths),
                split_files=[str(path) for path in split_paths],
                split_file_count=len(split_paths),
            )
        )

    for source in other_sources:
        source_manifests.append(
            SourceFileManifest(
                source_type=source.source_type,
                path=str(source.path),
                sha256=_sha256_file(source.path),
                size_bytes=source.path.stat().st_size,
                event_count=source_event_counts[source.path],
            )
        )

    return source_manifests


def _iter_text_lines(path: Path) -> Iterable[tuple[int, str]]:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        yield from enumerate(handle, start=1)


def _canonical_digest(timestamp: datetime, message: str) -> str:
    payload = f"dlt|{timestamp.isoformat()}|{message}".encode()
    return hashlib.sha256(payload).hexdigest()[:16]


def _event_sort_key(event: NormalizedEvent) -> tuple[datetime, str, int, str]:
    raw_line_number = event.attributes.get("original_line_number")
    if raw_line_number is None:
        raw_line_number = event.attributes.get("line_number", 0)

    try:
        line_number = int(raw_line_number)
    except (TypeError, ValueError):
        line_number = 0

    return (event.timestamp, event.source_file, line_number, event.event_id)


def _build_source_artifacts(
    *, events: Sequence[NormalizedEvent], sources: Sequence[SourceInput]
) -> dict[str, Sequence[dict[str, Any]]]:
    source_types = {source.source_type for source in sources}

    dlt_rows = [event.to_dict() for event in events if event.source_type == "dlt"]
    bus_rows = [event.to_dict() for event in events if event.source_type in {"bus_blf", "bus_asc"}]
    syslog_rows = [event.to_dict() for event in events if event.source_type == "syslog"]
    test_rows = [event.to_dict() for event in events if event.source_type.startswith("test_")]

    bus_signal_rows: list[dict[str, Any]] = []
    for event in events:
        if event.source_type not in {"bus_blf", "bus_asc"}:
            continue

        decoded_raw = event.attributes.get("decoded_signals")
        decoded_signals = decoded_raw if isinstance(decoded_raw, dict) else {}
        for signal_name, signal_value in sorted(decoded_signals.items()):
            bus_signal_rows.append(
                {
                    "event_id": event.event_id,
                    "timestamp": event.to_dict()["timestamp"],
                    "source_file": event.source_file,
                    "bus_channel": event.bus_channel,
                    "frame_id": event.frame_id,
                    "signal_name": str(signal_name),
                    "signal_value": signal_value,
                }
            )

    artifacts: dict[str, Sequence[dict[str, Any]]] = {}
    if "dlt" in source_types:
        artifacts["dlt.parsed.jsonl"] = dlt_rows
    if {"bus_blf", "bus_asc"} & source_types:
        artifacts["bus.frames.jsonl"] = bus_rows
        artifacts["bus.signals.jsonl"] = bus_signal_rows
    if "syslog" in source_types:
        artifacts["syslog.parsed.jsonl"] = syslog_rows
    if {source for source in source_types if source.startswith("test_")}:
        artifacts["test_failures.jsonl"] = test_rows

    return artifacts


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _deterministic_session_id(source_manifests: list[SourceFileManifest]) -> str:
    payload = "|".join(sorted(f"{item.path}:{item.sha256}" for item in source_manifests))
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"session-{digest[:12]}"
