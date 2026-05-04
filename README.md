# AutoPack

**Record once. Investigate anywhere.**

AutoPack is a **CLI-first deterministic evidence compiler** for automotive validation incidents.

It turns noisy run artifacts into a portable investigation pack that is readable by humans and automation, and suitable for later AI-assisted reasoning (optional, not required).

## What AutoPack is

- A Python CLI for deterministic incident preprocessing
- A structured evidence pack generator
- A validation tool for pack integrity and schema consistency

## What AutoPack is not

- Not a dashboard
- Not an MCP-first workflow
- Not an embeddings-first retrieval system
- Not a thin wrapper that uploads raw logs to an LLM

## Why deterministic evidence packs matter

Raw logs are high-volume and noisy. AutoPack first applies deterministic preprocessing so evidence becomes:

- structured (`timeline.jsonl`, `anomalies.jsonl`, `correlations.jsonl`)
- auditable (source hashes and counts in `manifest.json`)
- compact enough for reliable triage and later downstream analysis

## Phase 1 status

Implemented in this repository snapshot:

- project scaffold + Python packaging
- typed schema models (`Manifest`, `NormalizedEvent`, `Anomaly`, `Correlation`)
- pack writer + pack validator
- CLI commands:
  - `autopack build`
  - `autopack summarize`
  - `autopack validate-pack`
- tests for deterministic pack creation and validation

Not implemented yet in this slice:

- full DLT/BLF/ASC protocol-aware parsing adapters
- DBC signal decode path
- advanced normalization/compression/correlation modules

## Installation

From repository root:

1. Create and activate a Python 3.10+ environment
2. Install in editable mode with dev dependencies

## Build a pack

Example:

autopack build \
  --dlt logs/tcu.dlt \
  --asc logs/run.asc \
  --dbc db/tcu.dbc \
  --syslog logs/syslog.txt \
  --out out/incident-pack

## Summarize a pack

autopack summarize --pack out/incident-pack

## Validate a pack

autopack validate-pack --pack out/incident-pack

## Pack outputs

A generated pack includes:

- `manifest.json`
- `timeline.jsonl`
- `anomalies.jsonl`
- `correlations.jsonl`
- `summary.md`
- `SESSION.md`
- `DATA_FORMAT.md`
- `INVESTIGATION_GUIDE.md`
- `evidence/top_patterns.json`
- `evidence/timeline_windows.json`
- `evidence/root_cause_candidates.json`

## Development

One-command quality tasks are available via `Makefile`:

- `make lint`
- `make typecheck`
- `make test`
- `make check-file-length`
- `make check`

Pre-commit is configured with Ruff, mypy, and basic file hygiene hooks.

- Install hooks: `make pre-commit-install`
- Run all hooks manually: `make pre-commit-run`
