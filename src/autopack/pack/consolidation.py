"""Consolidation helpers for split source files."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from datetime import timezone
from pathlib import Path
from typing import Iterable
from typing import Sequence

from autopack.pack.analysis import extract_timestamp


@dataclass(slots=True)
class ConsolidatedLine:
    """Single normalized text line with deterministic ordering metadata."""

    source_path: Path
    source_ordinal: int
    line_number: int
    message: str
    timestamp: datetime | None


def consolidate_text_lines(paths: Sequence[Path]) -> list[ConsolidatedLine]:
    """Read and deterministically order lines across multiple text inputs."""
    collected: list[ConsolidatedLine] = []

    for source_ordinal, path in enumerate(paths):
        for line_number, line in _iter_text_lines(path):
            message = line.strip()
            if not message:
                continue

            collected.append(
                ConsolidatedLine(
                    source_path=path,
                    source_ordinal=source_ordinal,
                    line_number=line_number,
                    message=message,
                    timestamp=extract_timestamp(message),
                )
            )

    synthetic_floor = datetime(1970, 1, 1, tzinfo=timezone.utc)
    collected.sort(
        key=lambda item: (
            item.timestamp is None,
            item.timestamp or synthetic_floor,
            str(item.source_path),
            item.line_number,
            item.source_ordinal,
        )
    )
    return collected


def _iter_text_lines(path: Path) -> Iterable[tuple[int, str]]:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            yield line_number, line
