"""Unit tests for cross-source timestamp alignment."""

from __future__ import annotations

from pathlib import Path

import pytest

from autopack.cli.main import main
from autopack.utils import iter_jsonl


def test_timestamp_alignment_shifts_non_anchor_source(tmp_path: Path) -> None:
    dlt_path = tmp_path / "run.dlt"
    asc_path = tmp_path / "run.asc"
    dbc_path = tmp_path / "signals.dbc"
    out_path = tmp_path / "incident-pack"

    dlt_path.write_text(
        "2026-04-17T10:00:00Z ERROR modem disconnect\n",
        encoding="utf-8",
    )
    asc_path.write_text(
        "2026-04-17T09:59:00Z CH1 ID=0x123 DATA=11 22 ERROR bus timeout\n",
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

    timeline_rows = list(iter_jsonl(out_path / "timeline.jsonl"))
    bus_event = next(row for row in timeline_rows if row.get("source_type") == "bus_asc")

    assert bus_event.get("timestamp") == "2026-04-17T10:00:00Z"
    attributes = bus_event.get("attributes", {})
    assert attributes.get("timestamp_origin") == "parsed"
    assert attributes.get("timestamp_offset_seconds") == pytest.approx(60.0)
    assert attributes.get("original_timestamp") == "2026-04-17T09:59:00+00:00"
