"""Pack creation and validation tests."""

from __future__ import annotations

import json
from datetime import datetime
from datetime import timezone
from pathlib import Path

from autopack.cli.main import main
from autopack.pack.validator import validate_pack_directory
from autopack.pack.writer import write_investigation_pack
from autopack.schema import Anomaly
from autopack.schema import Correlation
from autopack.schema import Manifest
from autopack.schema import NormalizedEvent
from autopack.schema import SourceFileManifest


def test_writer_roundtrip_validation(tmp_path: Path) -> None:
    pack_dir = tmp_path / "incident-pack"

    timeline = [
        NormalizedEvent(
            event_id="evt-1",
            timestamp=datetime(2026, 4, 17, 10, 0, tzinfo=timezone.utc),
            source_type="dlt",
            source_file="input.dlt",
            severity="error",
            category="connectivity",
            message="modem disconnect detected",
            attributes={"line_number": 42},
            tags=["dlt", "connectivity"],
            correlation_keys={"ecu": "TCU"},
        )
    ]

    anomalies = [
        Anomaly(
            anomaly_id="an-1",
            kind="event",
            severity="error",
            start_time=timeline[0].timestamp,
            end_time=timeline[0].timestamp,
            event_ids=["evt-1"],
            evidence_sources=["input.dlt"],
            description="single disconnect anomaly",
            score=0.8,
            attributes={"source_types": ["dlt"], "categories": ["connectivity"]},
        )
    ]

    correlations = [
        Correlation(
            correlation_id="cor-1",
            rule="temporal_overlap_5s",
            confidence=0.7,
            window_start=timeline[0].timestamp,
            window_end=timeline[0].timestamp,
            event_ids=["evt-1"],
            source_types=["dlt"],
            summary="single-source temporal signal",
        )
    ]

    manifest = Manifest(
        pack_version="1.0.0",
        session_id="session-test",
        created_at=datetime(2026, 4, 17, 10, 0, tzinfo=timezone.utc),
        generator="autopack/test",
        source_files=[
            SourceFileManifest(
                source_type="dlt",
                path="input.dlt",
                sha256="a" * 64,
                size_bytes=128,
                event_count=1,
            )
        ],
        total_events=1,
        total_anomalies=1,
        total_correlations=1,
    )

    write_investigation_pack(
        output_dir=pack_dir,
        manifest=manifest,
        timeline=timeline,
        anomalies=anomalies,
        correlations=correlations,
        summary_markdown="# Summary\n\nA deterministic summary.",
        source_artifacts={"dlt.parsed.jsonl": [timeline[0].to_dict()]},
    )

    validation = validate_pack_directory(pack_dir)
    assert validation.valid, validation.errors


def test_cli_build_creates_valid_pack(tmp_path: Path) -> None:
    dlt_path = tmp_path / "run.dlt"
    asc_path = tmp_path / "run.asc"
    dbc_path = tmp_path / "signals.dbc"
    out_path = tmp_path / "incident-pack"

    dlt_path.write_text(
        "2026-04-17T10:00:00Z ECU reconnect attempt\n"
        "2026-04-17T10:00:01Z ERROR modem disconnect\n"
        "2026-04-17T10:00:02Z ERROR modem disconnect\n",
        encoding="utf-8",
    )
    asc_path.write_text(
        "2026-04-17T10:00:01Z CAN warning bus instability\n"
        "2026-04-17T10:00:03Z ERROR can timeout frame 0x123\n",
        encoding="utf-8",
    )
    dbc_path.write_text('VERSION "1.0"\n', encoding="utf-8")

    exit_code = main(
        [
            "build",
            "--dlt",
            str(dlt_path),
            "--asc",
            str(asc_path),
            "--dbc",
            str(dbc_path),
            "--out",
            str(out_path),
        ]
    )
    assert exit_code == 0

    validation = validate_pack_directory(out_path)
    assert validation.valid, validation.errors
    assert validation.manifest is not None
    assert validation.manifest.total_events >= 4
    assert validation.manifest.total_anomalies >= 1
    assert (out_path / "sources" / "dlt.parsed.jsonl").exists()
    assert (out_path / "sources" / "bus.frames.jsonl").exists()
    assert (out_path / "sources" / "bus.signals.jsonl").exists()


def test_validator_detects_manifest_count_mismatch(tmp_path: Path) -> None:
    dlt_path = tmp_path / "run.dlt"
    blf_path = tmp_path / "run.blf"
    dbc_path = tmp_path / "signals.dbc"
    out_path = tmp_path / "incident-pack"

    dlt_path.write_text("2026-04-17T10:00:00Z ERROR modem reset\n", encoding="utf-8")
    blf_path.write_text("2026-04-17T10:00:01Z ERROR bus timeout\n", encoding="utf-8")
    dbc_path.write_text('VERSION "1.0"\n', encoding="utf-8")

    exit_code = main(
        [
            "build",
            "--dlt",
            str(dlt_path),
            "--blf",
            str(blf_path),
            "--dbc",
            str(dbc_path),
            "--out",
            str(out_path),
        ]
    )
    assert exit_code == 0

    manifest_path = out_path / "manifest.json"
    manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest_data["total_events"] = manifest_data["total_events"] + 1
    manifest_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

    validation = validate_pack_directory(out_path)
    assert not validation.valid
    assert any("manifest.total_events" in error for error in validation.errors)


def test_validator_detects_missing_required_source_artifact(tmp_path: Path) -> None:
    dlt_path = tmp_path / "run.dlt"
    asc_path = tmp_path / "run.asc"
    dbc_path = tmp_path / "signals.dbc"
    out_path = tmp_path / "incident-pack"

    dlt_path.write_text("2026-04-17T10:00:00Z ERROR modem reset\n", encoding="utf-8")
    asc_path.write_text("2026-04-17T10:00:01Z ERROR can timeout frame 0x123\n", encoding="utf-8")
    dbc_path.write_text('VERSION "1.0"\n', encoding="utf-8")

    exit_code = main(
        [
            "build",
            "--dlt",
            str(dlt_path),
            "--asc",
            str(asc_path),
            "--dbc",
            str(dbc_path),
            "--out",
            str(out_path),
        ]
    )
    assert exit_code == 0

    (out_path / "sources" / "dlt.parsed.jsonl").unlink()

    validation = validate_pack_directory(out_path)
    assert not validation.valid
    assert any("Missing required source artifact" in error for error in validation.errors)


def test_cli_build_accepts_dlt_profile_and_vendor_and_records_notes(tmp_path: Path) -> None:
    dlt_path = tmp_path / "vendor.dlt"
    asc_path = tmp_path / "run.asc"
    dbc_path = tmp_path / "signals.dbc"
    out_path = tmp_path / "incident-pack"

    dlt_path.write_text(
        "2026-04-17T10:00:00Z ECU(TCU_MAIN) APID(MODEM) CTID(NET) ERROR drop\n",
        encoding="utf-8",
    )
    asc_path.write_text("2026-04-17T10:00:01Z INFO can frame\n", encoding="utf-8")
    dbc_path.write_text('VERSION "1.0"\n', encoding="utf-8")

    exit_code = main(
        [
            "build",
            "--dlt",
            str(dlt_path),
            "--dlt-profile",
            "oem_relaxed",
            "--dlt-vendor",
            "oem_ecu_beta",
            "--asc",
            str(asc_path),
            "--dbc",
            str(dbc_path),
            "--out",
            str(out_path),
        ]
    )
    assert exit_code == 0

    validation = validate_pack_directory(out_path)
    assert validation.valid, validation.errors

    manifest_payload = json.loads((out_path / "manifest.json").read_text(encoding="utf-8"))
    notes = manifest_payload.get("notes", [])
    assert isinstance(notes, list)
    assert any("DLT parse profile: oem_relaxed" in str(item) for item in notes)
    assert any("DLT vendor mapping: oem_ecu_beta" in str(item) for item in notes)
