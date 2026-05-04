"""Unit tests for bus parser adapter behavior."""

from __future__ import annotations

from pathlib import Path

from autopack.parsers.bus.adapter import parse_bus_trace


def test_parse_bus_trace_fallback_extracts_frame_fields(tmp_path: Path) -> None:
    asc_path = tmp_path / "run.asc"
    asc_path.write_text(
        "2026-04-17T10:00:01Z CH1 ID=0x123 DATA=11 22 33 44 ERROR bus timeout\n"
        "2026-04-17T10:00:02Z CH2 ID=0x124 DATA=AA BB WARN retry\n",
        encoding="utf-8",
    )

    frames, warnings = parse_bus_trace(asc_path)

    assert len(frames) == 2
    assert any("fallback" in warning.lower() for warning in warnings)

    first = frames[0]
    assert first.timestamp is not None
    assert first.channel == "1"
    assert first.frame_id == "0x123"
    assert first.arbitration_id == 0x123
    assert first.data_hex == "11223344"
    assert first.decoded_signals == {}


def test_parse_bus_trace_without_hex_fields_is_still_parsed(tmp_path: Path) -> None:
    blf_path = tmp_path / "run.blf"
    blf_path.write_text("2026-04-17T10:00:05Z WARN bus unstable\n", encoding="utf-8")

    frames, _ = parse_bus_trace(blf_path)

    assert len(frames) == 1
    only = frames[0]
    assert only.frame_id is None
    assert only.arbitration_id is None
    assert only.data_hex is None
