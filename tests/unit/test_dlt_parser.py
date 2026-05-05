"""Unit tests for DLT parser adapter."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterator

import pytest

from autopack.parsers.dlt import parse_dlt_file
from autopack.parsers.dlt import parse_dlt_line


def test_parse_dlt_line_extracts_named_fields() -> None:
    parsed = parse_dlt_line(
        "2026-04-17T10:00:01Z ECU:TCU APPID:MODEM CTXID:NET ERROR modem disconnect"
    )

    assert parsed.timestamp is not None
    assert parsed.ecu == "TCU"
    assert parsed.app_id == "MODEM"
    assert parsed.context_id == "NET"
    assert "modem disconnect" in parsed.message


def test_parse_dlt_line_supports_bracketed_fields() -> None:
    parsed = parse_dlt_line(
        "2026-04-17T10:00:02Z [APPid:COMM] [CTXID:RADIO] ECU=TCU WARN reconnect retry"
    )

    assert parsed.ecu == "TCU"
    assert parsed.app_id == "COMM"
    assert parsed.context_id == "RADIO"


def test_parse_dlt_line_handles_missing_fields() -> None:
    parsed = parse_dlt_line("plain dlt text without metadata")

    assert parsed.timestamp is None
    assert parsed.ecu is None
    assert parsed.app_id is None
    assert parsed.context_id is None
    assert parsed.message == "plain dlt text without metadata"


def test_parse_dlt_line_supports_oem_relaxed_profile() -> None:
    parsed = parse_dlt_line(
        "2026-04-17T10:00:03Z ECU(TCU_MAIN) APID(MODEM) CTID(NET) ERROR signal drop",
        profile="oem_relaxed",
    )

    assert parsed.ecu == "TCU_MAIN"
    assert parsed.app_id == "MODEM"
    assert parsed.context_id == "NET"


def test_parse_dlt_line_auto_detects_bracketed_profile() -> None:
    parsed = parse_dlt_line(
        "2026-04-17T10:00:04Z [ECU:TCU2] [APPID:DIAG] [CTXID:AUTH] WARN key mismatch",
        profile="auto",
    )

    assert parsed.ecu == "TCU2"
    assert parsed.app_id == "DIAG"
    assert parsed.context_id == "AUTH"


def test_parse_dlt_file_uses_text_fallback_when_library_missing(tmp_path: Path) -> None:
    dlt_path = tmp_path / "run.dlt"
    dlt_path.write_text(
        "2026-04-17T10:00:00Z ECU:TCU APPID:COMM CTXID:NET INFO boot\n",
        encoding="utf-8",
    )

    records, backend, warnings = parse_dlt_file(dlt_path)

    assert records
    assert backend in {"text-fallback", "pydlt"}
    assert any("DLT parser backend" in warning for warning in warnings)


def test_parse_dlt_file_emits_profile_selection_warning(tmp_path: Path) -> None:
    dlt_path = tmp_path / "run_oem.dlt"
    dlt_path.write_text(
        "2026-04-17T10:00:10Z ECU(TCU_A) APID(MODEM) CTID(RADIO) ERROR drop\n",
        encoding="utf-8",
    )

    records, backend, warnings = parse_dlt_file(dlt_path, profile="oem_relaxed")

    assert records
    assert backend in {"text-fallback", "pydlt"}
    assert any("DLT profile selection" in warning for warning in warnings)


def test_parse_dlt_file_vendor_mapping_changes_auto_profile_choice(tmp_path: Path) -> None:
    dlt_path = tmp_path / "vendor_order.dlt"
    dlt_path.write_text(
        "2026-04-17T10:00:11Z [APPID:COMM] [CTXID:RADIO] WARN retry\n",
        encoding="utf-8",
    )

    _records_default, _backend_default, warnings_default = parse_dlt_file(
        dlt_path,
        profile="auto",
        vendor="default",
    )
    _records_oem, _backend_oem, warnings_oem = parse_dlt_file(
        dlt_path,
        profile="auto",
        vendor="oem_tcu_alpha",
    )

    default_profile_warning = next(
        warning for warning in warnings_default if "DLT profile selection" in warning
    )
    oem_profile_warning = next(
        warning for warning in warnings_oem if "DLT profile selection" in warning
    )

    assert "autosar=1" in default_profile_warning
    assert "bracketed=1" in oem_profile_warning


def test_parse_dlt_file_uses_mocked_pydlt(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    class FakeMessage:
        def __init__(self) -> None:
            self.ecu_id = "ECU1"
            self.app_id = "APP1"
            self.context_id = "CTX1"

        def __str__(self) -> str:
            return "2026-04-17T10:00:00Z ERROR mocked pydlt message"

    class FakeReader:
        def __init__(self, _path: str) -> None:
            self._messages = [FakeMessage()]

        def __iter__(self) -> Iterator[FakeMessage]:
            return iter(self._messages)

    class FakePydltModule:
        DltFileReader = FakeReader

    monkeypatch.setitem(sys.modules, "pydlt", FakePydltModule())

    dlt_path = tmp_path / "mocked.dlt"
    dlt_path.write_text("placeholder\n", encoding="utf-8")

    records, backend, warnings = parse_dlt_file(dlt_path)

    assert backend == "pydlt"
    assert len(records) == 1
    assert records[0].parsed.ecu == "ECU1"
    assert records[0].parsed.app_id == "APP1"
    assert records[0].parsed.context_id == "CTX1"
    assert any("pydlt" in warning.lower() for warning in warnings)
