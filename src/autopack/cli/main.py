"""CLI entrypoint for AutoPack."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from autopack.cli.commands import command_build
from autopack.cli.commands import command_summarize
from autopack.cli.commands import command_validate_pack
from autopack.parsers.dlt import SUPPORTED_DLT_PROFILES
from autopack.parsers.dlt import SUPPORTED_DLT_VENDORS


def build_parser() -> argparse.ArgumentParser:
    """Create the top-level AutoPack argument parser."""
    parser = argparse.ArgumentParser(
        prog="autopack",
        description="CLI-first deterministic automotive investigation pack builder",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_parser_cmd = subparsers.add_parser(
        "build",
        help="Build an investigation pack from source artifacts",
    )
    build_parser_cmd.add_argument(
        "--dlt",
        action="append",
        required=True,
        help="Path to DLT log file (repeat for split inputs)",
    )
    build_parser_cmd.add_argument(
        "--dlt-profile",
        default="auto",
        choices=list(SUPPORTED_DLT_PROFILES),
        help="DLT parser profile (auto, autosar, bracketed, oem_relaxed)",
    )
    build_parser_cmd.add_argument(
        "--dlt-vendor",
        default="default",
        choices=list(SUPPORTED_DLT_VENDORS),
        help="DLT vendor mapping key for auto profile selection",
    )
    build_parser_cmd.add_argument("--blf", required=False, help="Path to BLF bus trace file")
    build_parser_cmd.add_argument("--asc", required=False, help="Path to ASC bus trace file")
    build_parser_cmd.add_argument("--dbc", required=True, help="Path to DBC file")
    build_parser_cmd.add_argument("--syslog", required=False, help="Path to syslog text file")
    build_parser_cmd.add_argument("--junit", required=False, help="Path to JUnit XML report")
    build_parser_cmd.add_argument("--pytest-log", required=False, help="Path to pytest log file")
    build_parser_cmd.add_argument(
        "--artifacts-dir", required=False, help="Path to test artifacts directory"
    )
    build_parser_cmd.add_argument(
        "--out", required=True, help="Output investigation pack directory"
    )
    build_parser_cmd.add_argument(
        "--session-id", required=False, help="Optional explicit session ID"
    )
    build_parser_cmd.set_defaults(handler=command_build)

    summarize_parser_cmd = subparsers.add_parser(
        "summarize",
        help="Summarize an existing investigation pack",
    )
    summarize_parser_cmd.add_argument(
        "--pack", required=True, help="Path to investigation pack directory"
    )
    summarize_parser_cmd.set_defaults(handler=command_summarize)

    validate_parser_cmd = subparsers.add_parser(
        "validate-pack",
        help="Validate investigation pack integrity and schema",
    )
    validate_parser_cmd.add_argument(
        "--pack", required=True, help="Path to investigation pack directory"
    )
    validate_parser_cmd.set_defaults(handler=command_validate_pack)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the AutoPack CLI."""
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
