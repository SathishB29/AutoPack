"""Command handlers for AutoPack CLI."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from autopack.pack.pipeline import build_pack_from_sources
from autopack.pack.validator import validate_pack_directory
from autopack.utils import iter_jsonl
from autopack.utils import read_json


def command_build(args: Any) -> int:
    """Execute `autopack build`."""
    try:
        dlt_paths = [Path(path) for path in args.dlt]
        build_kwargs: dict[str, Any] = {
            "dlt_paths": dlt_paths,
            "dlt_profile": args.dlt_profile,
            "dlt_vendor": args.dlt_vendor,
            "blf_path": Path(args.blf) if args.blf else None,
            "asc_path": Path(args.asc) if args.asc else None,
            "dbc_path": Path(args.dbc),
            "syslog_path": Path(args.syslog) if args.syslog else None,
            "junit_path": Path(args.junit) if args.junit else None,
            "pytest_log_path": Path(args.pytest_log) if args.pytest_log else None,
            "artifacts_dir": Path(args.artifacts_dir) if args.artifacts_dir else None,
            "output_dir": Path(args.out),
            "session_id": args.session_id,
        }

        result = build_pack_from_sources(**build_kwargs)
    except Exception as exc:  # noqa: BLE001
        print(f"Build failed: {exc}", file=sys.stderr)
        return 1

    print(f"Pack generated at: {result.output_dir}")
    print("Artifacts written:")
    for relative in result.files_written:
        print(f"- {relative}")
    return 0


def command_summarize(args: Any) -> int:
    """Execute `autopack summarize`."""
    pack_dir = Path(args.pack)
    validation = validate_pack_directory(pack_dir)
    if not validation.valid:
        print("Pack validation failed. Cannot summarize.", file=sys.stderr)
        for error in validation.errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    manifest_payload = read_json(pack_dir / "manifest.json")
    if not isinstance(manifest_payload, dict):
        print("Invalid manifest format.", file=sys.stderr)
        return 1

    anomalies = list(iter_jsonl(pack_dir / "anomalies.jsonl"))
    correlations = list(iter_jsonl(pack_dir / "correlations.jsonl"))

    print("AutoPack Incident Summary")
    print("========================")
    print(f"Session ID: {manifest_payload.get('session_id')}")
    print(f"Total events: {manifest_payload.get('total_events')}")
    print(f"Total anomalies: {manifest_payload.get('total_anomalies')}")
    print(f"Total correlations: {manifest_payload.get('total_correlations')}")

    print("\nTop anomalies:")
    for item in anomalies[:5]:
        print(
            f"- {item.get('anomaly_id')}: {item.get('kind')} ({item.get('severity')}) "
            f"events={len(item.get('event_ids', []))}"
        )

    if not anomalies:
        print("- none")

    print("\nTop correlations:")
    for item in correlations[:5]:
        confidence = item.get("confidence", 0.0)
        try:
            confidence_display = f"{float(confidence):.2f}"
        except (TypeError, ValueError):
            confidence_display = json.dumps(confidence)
        print(f"- {item.get('correlation_id')}: {item.get('rule')} confidence={confidence_display}")

    if not correlations:
        print("- none")

    return 0


def command_validate_pack(args: Any) -> int:
    """Execute `autopack validate-pack`."""
    pack_dir = Path(args.pack)
    validation = validate_pack_directory(pack_dir)

    if validation.valid:
        print(f"Pack is valid: {pack_dir}")
        if validation.warnings:
            print("Warnings:")
            for warning in validation.warnings:
                print(f"- {warning}")
        return 0

    print(f"Pack is invalid: {pack_dir}", file=sys.stderr)
    for error in validation.errors:
        print(f"- {error}", file=sys.stderr)
    if validation.warnings:
        print("Warnings:", file=sys.stderr)
        for warning in validation.warnings:
            print(f"- {warning}", file=sys.stderr)
    return 1
