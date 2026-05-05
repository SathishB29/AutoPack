"""Validation checks for generated investigation packs."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from autopack.schema import Anomaly
from autopack.schema import Correlation
from autopack.schema import Manifest
from autopack.schema import NormalizedEvent
from autopack.schema import SourceFileManifest
from autopack.utils.io import count_jsonl_rows
from autopack.utils.io import iter_jsonl
from autopack.utils.io import read_json


@dataclass(slots=True)
class PackValidationResult:
    """Structured output from pack validation."""

    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    manifest: Manifest | None = None


def validate_pack_directory(pack_dir: Path) -> PackValidationResult:
    """Validate required pack files, schemas, and aggregate counts."""
    errors: list[str] = []
    warnings: list[str] = []

    if not pack_dir.exists():
        return PackValidationResult(valid=False, errors=[f"Pack path does not exist: {pack_dir}"])

    if not pack_dir.is_dir():
        return PackValidationResult(
            valid=False, errors=[f"Pack path is not a directory: {pack_dir}"]
        )

    required_files = [
        "manifest.json",
        "timeline.jsonl",
        "anomalies.jsonl",
        "correlations.jsonl",
        "summary.md",
    ]

    for relative in required_files:
        candidate = pack_dir / relative
        if not candidate.exists():
            errors.append(f"Missing required file: {relative}")

    if errors:
        return PackValidationResult(valid=False, errors=errors)

    manifest: Manifest | None = None
    try:
        raw_manifest = read_json(pack_dir / "manifest.json")
        if not isinstance(raw_manifest, dict):
            raise ValueError("manifest.json must contain a JSON object")
        manifest = Manifest.from_dict(raw_manifest)
    except Exception as exc:  # noqa: BLE001
        errors.append(f"Invalid manifest.json: {exc}")
        return PackValidationResult(valid=False, errors=errors)

    try:
        _validate_jsonl_records(pack_dir / "timeline.jsonl", NormalizedEvent)
    except Exception as exc:  # noqa: BLE001
        errors.append(str(exc))

    try:
        _validate_jsonl_records(pack_dir / "anomalies.jsonl", Anomaly)
    except Exception as exc:  # noqa: BLE001
        errors.append(str(exc))

    try:
        _validate_jsonl_records(pack_dir / "correlations.jsonl", Correlation)
    except Exception as exc:  # noqa: BLE001
        errors.append(str(exc))

    if not (pack_dir / "summary.md").read_text(encoding="utf-8").strip():
        errors.append("summary.md must not be empty")

    if manifest is not None:
        timeline_count = count_jsonl_rows(pack_dir / "timeline.jsonl")
        anomalies_count = count_jsonl_rows(pack_dir / "anomalies.jsonl")
        correlations_count = count_jsonl_rows(pack_dir / "correlations.jsonl")

        if timeline_count != manifest.total_events:
            errors.append(
                "timeline.jsonl row count does not match manifest.total_events "
                f"({timeline_count} != {manifest.total_events})"
            )
        if anomalies_count != manifest.total_anomalies:
            errors.append(
                "anomalies.jsonl row count does not match manifest.total_anomalies "
                f"({anomalies_count} != {manifest.total_anomalies})"
            )
        if correlations_count != manifest.total_correlations:
            errors.append(
                "correlations.jsonl row count does not match manifest.total_correlations "
                f"({correlations_count} != {manifest.total_correlations})"
            )

        _validate_source_artifacts(pack_dir=pack_dir, manifest=manifest, errors=errors)

    evidence_dir = pack_dir / "evidence"
    if evidence_dir.exists() and evidence_dir.is_dir():
        for evidence_file in [
            evidence_dir / "top_patterns.json",
            evidence_dir / "timeline_windows.json",
            evidence_dir / "root_cause_candidates.json",
        ]:
            if evidence_file.exists():
                try:
                    read_json(evidence_file)
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"Invalid evidence JSON file {evidence_file.name}: {exc}")
            else:
                warnings.append(f"Missing optional evidence file: evidence/{evidence_file.name}")
    else:
        warnings.append("Missing optional directory: evidence/")

    return PackValidationResult(
        valid=not errors, errors=errors, warnings=warnings, manifest=manifest
    )


def _validate_jsonl_records(
    file_path: Path,
    model_type: type[NormalizedEvent] | type[Anomaly] | type[Correlation],
) -> None:
    for line_no, payload in enumerate(iter_jsonl(file_path), start=1):
        try:
            model_type.from_dict(payload)
        except Exception as exc:  # noqa: BLE001
            raise ValueError(
                f"Invalid record in {file_path.name} at line {line_no}: {exc}"
            ) from exc


def _validate_source_artifacts(pack_dir: Path, manifest: Manifest, errors: list[str]) -> None:
    source_dir = pack_dir / "sources"
    expected = _expected_source_artifacts(manifest.source_files)

    if not expected:
        return

    if not source_dir.exists() or not source_dir.is_dir():
        errors.append("Missing required directory for source artifacts: sources/")
        return

    row_counts: dict[str, int] = {}
    for relative in sorted(expected):
        candidate = source_dir / relative
        if not candidate.exists():
            errors.append(f"Missing required source artifact: sources/{relative}")
            continue

        try:
            row_counts[relative] = _count_valid_jsonl_rows(candidate)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"Invalid source artifact {relative}: {exc}")

    dlt_expected = _manifest_event_count(manifest.source_files, {"dlt"})
    bus_expected = _manifest_event_count(manifest.source_files, {"bus_blf", "bus_asc"})
    syslog_expected = _manifest_event_count(manifest.source_files, {"syslog"})
    test_expected = _manifest_event_count(
        manifest.source_files,
        {"test_junit", "test_pytest"},
    )

    if "dlt.parsed.jsonl" in row_counts and row_counts["dlt.parsed.jsonl"] != dlt_expected:
        errors.append(
            "sources/dlt.parsed.jsonl row count does not match manifest DLT event_count "
            f"({row_counts['dlt.parsed.jsonl']} != {dlt_expected})"
        )
    if "bus.frames.jsonl" in row_counts and row_counts["bus.frames.jsonl"] != bus_expected:
        errors.append(
            "sources/bus.frames.jsonl row count does not match manifest bus event_count "
            f"({row_counts['bus.frames.jsonl']} != {bus_expected})"
        )
    if "syslog.parsed.jsonl" in row_counts and row_counts["syslog.parsed.jsonl"] != syslog_expected:
        errors.append(
            "sources/syslog.parsed.jsonl row count does not match manifest syslog event_count "
            f"({row_counts['syslog.parsed.jsonl']} != {syslog_expected})"
        )
    if "test_failures.jsonl" in row_counts and row_counts["test_failures.jsonl"] != test_expected:
        errors.append(
            "sources/test_failures.jsonl row count does not match manifest test event_count "
            f"({row_counts['test_failures.jsonl']} != {test_expected})"
        )


def _expected_source_artifacts(source_files: Iterable[SourceFileManifest]) -> set[str]:
    source_types = {source.source_type for source in source_files}

    expected: set[str] = set()
    if "dlt" in source_types:
        expected.add("dlt.parsed.jsonl")
    if {"bus_blf", "bus_asc"} & source_types:
        expected.add("bus.frames.jsonl")
        expected.add("bus.signals.jsonl")
    if "syslog" in source_types:
        expected.add("syslog.parsed.jsonl")
    if {source for source in source_types if source.startswith("test_")}:
        expected.add("test_failures.jsonl")

    return expected


def _manifest_event_count(
    source_files: Iterable[SourceFileManifest],
    source_types: set[str],
) -> int:
    return sum(source.event_count for source in source_files if source.source_type in source_types)


def _count_valid_jsonl_rows(path: Path) -> int:
    count = 0
    for _ in iter_jsonl(path):
        count += 1
    return count
