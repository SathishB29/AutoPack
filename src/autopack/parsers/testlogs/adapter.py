"""Deterministic test-log parsing helpers for JUnit and pytest text logs."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime
from datetime import timezone
from pathlib import Path

_TIMESTAMP_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)
_PYTEST_CASE_RE = re.compile(
    r"^(?P<test_id>\S+)\s+(?P<status>PASSED|FAILED|ERROR|SKIPPED)(?:\s+in\s+(?P<duration>[0-9.]+)s)?",
    re.IGNORECASE,
)


@dataclass(slots=True)
class ParsedTestRecord:
    """Structured test evidence extracted from logs."""

    line_number: int
    timestamp: datetime | None
    framework: str
    test_id: str
    status: str
    duration_seconds: float | None
    failure_kind: str | None
    message: str


def parse_test_log_file(source_type: str, path: Path) -> tuple[list[ParsedTestRecord], list[str]]:
    """Parse JUnit or pytest logs into normalized test evidence records."""
    if source_type == "test_junit":
        records = _parse_junit(path)
    elif source_type == "test_pytest":
        records = _parse_pytest_text(path)
    else:
        records = []

    warnings = [f"test parser used for {path.name} ({source_type}): {len(records)} rows"]
    return records, warnings


def _parse_junit(path: Path) -> list[ParsedTestRecord]:
    tree = ET.parse(path)
    root = tree.getroot()

    records: list[ParsedTestRecord] = []
    for line_number, testcase in enumerate(root.iter("testcase"), start=1):
        classname = _to_text(testcase.attrib.get("classname"))
        name = _to_text(testcase.attrib.get("name")) or f"testcase_{line_number}"
        test_id = f"{classname}.{name}" if classname else name

        duration = _to_float(testcase.attrib.get("time"))
        suite_timestamp = _find_parent_suite_timestamp(root, testcase)

        failure = testcase.find("failure")
        error = testcase.find("error")
        skipped = testcase.find("skipped")

        if failure is not None:
            status = "failed"
            failure_kind = _to_text(failure.attrib.get("type")) or "failure"
            message = _to_text(failure.attrib.get("message")) or _to_text(failure.text) or "failure"
        elif error is not None:
            status = "error"
            failure_kind = _to_text(error.attrib.get("type")) or "error"
            message = _to_text(error.attrib.get("message")) or _to_text(error.text) or "error"
        elif skipped is not None:
            status = "skipped"
            failure_kind = None
            message = _to_text(skipped.attrib.get("message")) or "skipped"
        else:
            status = "passed"
            failure_kind = None
            message = "passed"

        records.append(
            ParsedTestRecord(
                line_number=line_number,
                timestamp=suite_timestamp,
                framework="junit",
                test_id=test_id,
                status=status,
                duration_seconds=duration,
                failure_kind=failure_kind,
                message=message,
            )
        )

    return records


def _find_parent_suite_timestamp(root: ET.Element, testcase: ET.Element) -> datetime | None:
    for testsuite in root.iter("testsuite"):
        if testcase in list(testsuite):
            timestamp = _to_text(testsuite.attrib.get("timestamp"))
            if timestamp is not None:
                extracted = _extract_timestamp(timestamp)
                if extracted is not None:
                    return extracted
    return None


def _parse_pytest_text(path: Path) -> list[ParsedTestRecord]:
    records: list[ParsedTestRecord] = []

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            normalized = raw_line.strip()
            if not normalized:
                continue

            match = _PYTEST_CASE_RE.match(normalized)
            if match is None:
                continue

            raw_status = _to_text(match.group("status")) or "unknown"
            status = raw_status.lower()
            duration = _to_float(match.group("duration"))
            failure_kind = status if status in {"failed", "error"} else None

            records.append(
                ParsedTestRecord(
                    line_number=line_number,
                    timestamp=_extract_timestamp(normalized),
                    framework="pytest",
                    test_id=_to_text(match.group("test_id")) or f"pytest_case_{line_number}",
                    status=status,
                    duration_seconds=duration,
                    failure_kind=failure_kind,
                    message=normalized,
                )
            )

    return records


def _extract_timestamp(line: str) -> datetime | None:
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


def _to_float(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _to_text(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    return text if text else None
