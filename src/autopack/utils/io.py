"""I/O helpers for JSON and JSONL artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from typing import Iterable
from typing import cast


def ensure_directory(path: Path) -> None:
    """Create directory recursively if needed."""
    path.mkdir(parents=True, exist_ok=True)


def write_json(path: Path, payload: dict[str, Any] | list[Any]) -> None:
    """Write UTF-8 JSON with stable formatting."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def read_json(path: Path) -> dict[str, Any] | list[Any]:
    """Read UTF-8 JSON document."""
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    if not isinstance(payload, (dict, list)):
        raise ValueError(
            f"JSON root must be an object or array in {path}, got {type(payload).__name__}"
        )

    return cast(dict[str, Any] | list[Any], payload)


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    """Write JSONL rows and return row count."""
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True))
            handle.write("\n")
            count += 1
    return count


def iter_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    """Iterate over JSONL rows while skipping empty lines."""
    with path.open("r", encoding="utf-8") as handle:
        for index, line in enumerate(handle, start=1):
            raw = line.strip()
            if not raw:
                continue
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL at {path}:{index}: {exc.msg}") from exc

            if not isinstance(parsed, dict):
                raise ValueError(f"Invalid JSONL at {path}:{index}: expected object per line")

            yield parsed


def count_jsonl_rows(path: Path) -> int:
    """Count non-empty JSONL rows."""
    with path.open("r", encoding="utf-8") as handle:
        return sum(1 for line in handle if line.strip())
