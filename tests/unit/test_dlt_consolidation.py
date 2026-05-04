"""Tests for split DLT consolidation behavior."""

from __future__ import annotations

from pathlib import Path

from autopack.cli.main import main
from autopack.pack.validator import validate_pack_directory
from autopack.utils import iter_jsonl
from autopack.utils import read_json


def test_cli_build_with_split_dlt_consolidates_manifest(tmp_path: Path) -> None:
    split_one = tmp_path / "split1.dlt"
    split_two = tmp_path / "split2.dlt"
    split_three = tmp_path / "split3.dlt"
    asc_path = tmp_path / "run.asc"
    dbc_path = tmp_path / "signals.dbc"
    out_path = tmp_path / "incident-pack"

    split_one.write_text(
        "2026-04-17T10:00:00Z INFO boot\n2026-04-17T10:00:01Z ERROR modem disconnect\n",
        encoding="utf-8",
    )
    split_two.write_text(
        "2026-04-17T10:00:01Z ERROR modem disconnect\n2026-04-17T10:00:02Z WARN reconnect retry\n",
        encoding="utf-8",
    )
    split_three.write_text(
        "2026-04-17T09:59:59Z INFO preflight\n",
        encoding="utf-8",
    )

    asc_path.write_text("2026-04-17T10:00:03Z ERROR can timeout frame 0x1\n", encoding="utf-8")
    dbc_path.write_text('VERSION "1.0"\n', encoding="utf-8")

    exit_code = main(
        [
            "build",
            "--dlt",
            str(split_one),
            "--dlt",
            str(split_two),
            "--dlt",
            str(split_three),
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

    manifest_payload = read_json(out_path / "manifest.json")
    assert isinstance(manifest_payload, dict)

    source_files = manifest_payload.get("source_files", [])
    assert isinstance(source_files, list)

    dlt_entries = [
        entry
        for entry in source_files
        if isinstance(entry, dict) and entry.get("source_type") == "dlt"
    ]

    assert len(dlt_entries) == 1
    dlt_entry = dlt_entries[0]
    assert dlt_entry.get("path") == "dlt_consolidated"
    assert dlt_entry.get("split_file_count") == 3

    split_paths = dlt_entry.get("split_files")
    assert isinstance(split_paths, list)
    assert split_paths == [str(split_one), str(split_two), str(split_three)]

    parse_warnings = manifest_payload.get("parse_warnings", [])
    assert isinstance(parse_warnings, list)
    assert any("Duplicate DLT canonical digest" in str(item) for item in parse_warnings)
    assert any("DLT parser backend" in str(item) for item in parse_warnings)


def test_split_dlt_timeline_uses_deterministic_ordering(tmp_path: Path) -> None:
    split_one = tmp_path / "split1.dlt"
    split_two = tmp_path / "split2.dlt"
    asc_path = tmp_path / "run.asc"
    dbc_path = tmp_path / "signals.dbc"
    out_path = tmp_path / "incident-pack"

    split_one.write_text(
        "2026-04-17T10:00:03Z INFO third\n2026-04-17T10:00:04Z INFO fourth\n",
        encoding="utf-8",
    )
    split_two.write_text(
        "2026-04-17T10:00:01Z INFO first\n2026-04-17T10:00:02Z INFO second\n",
        encoding="utf-8",
    )

    asc_path.write_text("2026-04-17T10:00:10Z INFO bus message\n", encoding="utf-8")
    dbc_path.write_text('VERSION "1.0"\n', encoding="utf-8")

    exit_code = main(
        [
            "build",
            "--dlt",
            str(split_one),
            "--dlt",
            str(split_two),
            "--asc",
            str(asc_path),
            "--dbc",
            str(dbc_path),
            "--out",
            str(out_path),
        ]
    )
    assert exit_code == 0

    dlt_rows = [
        row for row in iter_jsonl(out_path / "timeline.jsonl") if row.get("source_type") == "dlt"
    ]

    ordering = [
        (
            str(row.get("timestamp")),
            str(row.get("source_file")),
            int(
                row.get("attributes", {}).get(
                    "original_line_number", row.get("attributes", {}).get("line_number", 0)
                )
            ),
        )
        for row in dlt_rows
    ]

    assert ordering == sorted(ordering)
