"""Unit tests for syslog and test-log parser adapters."""

from __future__ import annotations

from pathlib import Path

from autopack.cli.main import main
from autopack.pack.validator import validate_pack_directory
from autopack.parsers.syslog.adapter import parse_syslog_file
from autopack.parsers.testlogs.adapter import parse_test_log_file


def test_parse_syslog_file_extracts_common_fields(tmp_path: Path) -> None:
    syslog_path = tmp_path / "syslog.log"
    syslog_path.write_text(
        "2026-04-17T10:00:01Z host1 modemd[321]: ERROR reconnect failed\n",
        encoding="utf-8",
    )

    rows, warnings = parse_syslog_file(syslog_path)

    assert len(rows) == 1
    row = rows[0]
    assert row.timestamp is not None
    assert row.hostname == "host1"
    assert row.process == "modemd"
    assert row.pid == "321"
    assert "reconnect failed" in row.message
    assert any("syslog parser used" in warning for warning in warnings)


def test_parse_test_log_file_parses_junit_and_pytest(tmp_path: Path) -> None:
    junit_path = tmp_path / "report.xml"
    junit_path.write_text(
        '<testsuite timestamp="2026-04-17T10:00:01Z">'
        '<testcase classname="suite.mod" name="test_ok" time="0.12" />'
        '<testcase classname="suite.mod" name="test_fail" time="0.34">'
        '<failure type="AssertionError" message="expected 1" />'
        "</testcase>"
        "</testsuite>",
        encoding="utf-8",
    )

    pytest_path = tmp_path / "pytest.log"
    pytest_path.write_text(
        "tests/test_mod.py::test_case PASSED in 0.10s\n"
        "tests/test_mod.py::test_other FAILED in 0.22s\n",
        encoding="utf-8",
    )

    junit_rows, junit_warnings = parse_test_log_file("test_junit", junit_path)
    pytest_rows, pytest_warnings = parse_test_log_file("test_pytest", pytest_path)

    assert len(junit_rows) == 2
    assert junit_rows[0].framework == "junit"
    assert junit_rows[1].status == "failed"
    assert junit_rows[1].failure_kind == "AssertionError"
    assert any("test parser used" in warning for warning in junit_warnings)

    assert len(pytest_rows) == 2
    assert pytest_rows[0].framework == "pytest"
    assert pytest_rows[0].status == "passed"
    assert pytest_rows[1].status == "failed"
    assert any("test parser used" in warning for warning in pytest_warnings)


def test_cli_build_with_syslog_and_junit_emits_source_artifacts(tmp_path: Path) -> None:
    dlt_path = tmp_path / "run.dlt"
    asc_path = tmp_path / "run.asc"
    dbc_path = tmp_path / "signals.dbc"
    syslog_path = tmp_path / "syslog.log"
    junit_path = tmp_path / "report.xml"
    out_path = tmp_path / "incident-pack"

    dlt_path.write_text("2026-04-17T10:00:00Z ERROR modem reset\n", encoding="utf-8")
    asc_path.write_text("2026-04-17T10:00:01Z ID=0x123 DATA=11 22 WARN bus\n", encoding="utf-8")
    dbc_path.write_text('VERSION "1.0"\n', encoding="utf-8")
    syslog_path.write_text(
        "2026-04-17T10:00:02Z host1 netd[55]: ERROR link down\n",
        encoding="utf-8",
    )
    junit_path.write_text(
        '<testsuite timestamp="2026-04-17T10:00:03Z">'
        '<testcase classname="suite.mod" name="test_a" time="0.11">'
        '<failure type="AssertionError" message="boom" />'
        "</testcase>"
        "</testsuite>",
        encoding="utf-8",
    )

    exit_code = main(
        [
            "build",
            "--dlt",
            str(dlt_path),
            "--asc",
            str(asc_path),
            "--dbc",
            str(dbc_path),
            "--syslog",
            str(syslog_path),
            "--junit",
            str(junit_path),
            "--out",
            str(out_path),
        ]
    )

    assert exit_code == 0
    validation = validate_pack_directory(out_path)
    assert validation.valid, validation.errors
    assert (out_path / "sources" / "syslog.parsed.jsonl").exists()
    assert (out_path / "sources" / "test_failures.jsonl").exists()
