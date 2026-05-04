"""Deterministic syslog parsing helpers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from datetime import timezone
from pathlib import Path

_TIMESTAMP_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)
_RFC3164_RE = re.compile(
    r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(?P<host>\S+)\s+(?P<proc>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)
_HOST_PROC_RE = re.compile(
    r"^(?:\S+\s+)?(?P<host>[\w.-]+)\s+(?P<proc>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)


@dataclass(slots=True)
class ParsedSyslogLine:
    """Structured syslog fields extracted from one line."""

    line_number: int
    timestamp: datetime | None
    hostname: str | None
    process: str | None
    pid: str | None
    message: str


def parse_syslog_file(path: Path) -> tuple[list[ParsedSyslogLine], list[str]]:
    """Parse syslog-style text files into structured records."""
    records: list[ParsedSyslogLine] = []

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            normalized = raw_line.strip()
            if not normalized:
                continue

            timestamp = _extract_timestamp(normalized)
            hostname, process, pid, message = _extract_fields(normalized)

            records.append(
                ParsedSyslogLine(
                    line_number=line_number,
                    timestamp=timestamp,
                    hostname=hostname,
                    process=process,
                    pid=pid,
                    message=message,
                )
            )

    warnings = [f"syslog parser used for {path.name}: {len(records)} rows"]
    return records, warnings


def _extract_fields(line: str) -> tuple[str | None, str | None, str | None, str]:
    match = _RFC3164_RE.match(line)
    if match is not None:
        return (
            _to_text(match.group("host")),
            _to_text(match.group("proc")),
            _to_text(match.group("pid")),
            _to_text(match.group("msg")) or line,
        )

    stripped = _strip_leading_timestamp(line)
    generic = _HOST_PROC_RE.match(stripped)
    if generic is not None:
        return (
            _to_text(generic.group("host")),
            _to_text(generic.group("proc")),
            _to_text(generic.group("pid")),
            _to_text(generic.group("msg")) or stripped,
        )

    return None, None, None, stripped


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


def _strip_leading_timestamp(line: str) -> str:
    match = _TIMESTAMP_RE.search(line)
    if match is None:
        return line
    return line[match.end() :].strip()


def _to_text(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    return text if text else None
