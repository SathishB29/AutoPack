"""Enforce a maximum line count per Python source file."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Iterable

DEFAULT_MAX_LINES = 400
DEFAULT_SCAN_ROOTS = ("src", "tests")
SKIP_DIR_NAMES = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    "build",
    "dist",
}


def iter_python_files(paths: Iterable[Path]) -> Iterable[Path]:
    """Yield Python files under the provided paths, skipping cache/build directories."""
    for path in paths:
        if not path.exists():
            continue

        if path.is_file():
            if path.suffix == ".py":
                yield path
            continue

        for candidate in path.rglob("*.py"):
            if any(part in SKIP_DIR_NAMES for part in candidate.parts):
                continue
            yield candidate


def count_file_lines(path: Path) -> int:
    """Count physical lines in a UTF-8 text file."""
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        return sum(1 for _ in handle)


def main() -> int:
    """CLI entrypoint for max-line enforcement."""
    parser = argparse.ArgumentParser(
        description="Fail when any Python file exceeds a configured line-count limit."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=list(DEFAULT_SCAN_ROOTS),
        help="Files or directories to scan (defaults to: src tests)",
    )
    parser.add_argument(
        "--max-lines",
        type=int,
        default=DEFAULT_MAX_LINES,
        help=f"Maximum allowed lines per Python file (default: {DEFAULT_MAX_LINES})",
    )
    args = parser.parse_args()

    input_paths = [Path(item) for item in args.paths]
    max_lines: int = args.max_lines

    violations: list[tuple[Path, int]] = []

    for file_path in sorted(iter_python_files(input_paths)):
        line_count = count_file_lines(file_path)
        if line_count > max_lines:
            violations.append((file_path, line_count))

    if not violations:
        print(f"OK: all scanned Python files are <= {max_lines} lines")
        return 0

    print(f"ERROR: found {len(violations)} Python file(s) exceeding {max_lines} lines:")
    for file_path, line_count in violations:
        print(f"- {file_path}: {line_count} lines")

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
