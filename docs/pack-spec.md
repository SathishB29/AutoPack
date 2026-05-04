# AutoPack Investigation Pack Spec (Phase 1)

## Overview

An investigation pack is a portable directory that combines machine-readable evidence and human-readable guidance.

## Required top-level files

- `manifest.json`
- `timeline.jsonl`
- `anomalies.jsonl`
- `correlations.jsonl`
- `summary.md`

## Generated helper docs

- `SESSION.md`
- `DATA_FORMAT.md`
- `INVESTIGATION_GUIDE.md`

## Evidence directory

- `evidence/top_patterns.json`
- `evidence/timeline_windows.json`
- `evidence/root_cause_candidates.json`

## File semantics

### `manifest.json`

Contains pack metadata and aggregate counts.

Key fields:

- `pack_version`
- `session_id`
- `created_at` (UTC ISO-8601)
- `generator`
- `source_files[]` with:
  - `source_type`
  - `path`
  - `sha256`
  - `size_bytes`
  - `event_count`
- `total_events`
- `total_anomalies`
- `total_correlations`
- `parse_warnings[]`
- `notes[]`

### `timeline.jsonl`

Canonical normalized event stream.

Each record includes (or supports):

- `event_id`
- `timestamp`
- `source_type`
- `source_file`
- `ecu`
- `app_id`
- `context_id`
- `bus_channel`
- `frame_id`
- `signal_name`
- `severity`
- `category`
- `message`
- `attributes`
- `tags`
- `correlation_keys`

### `anomalies.jsonl`

Deterministic anomaly windows derived from normalized events.

Each record includes:

- `anomaly_id`
- `kind`
- `severity`
- `start_time`
- `end_time`
- `event_ids[]`
- `evidence_sources[]`
- `description`
- `score`
- `attributes`

### `correlations.jsonl`

Cross-source links between anomaly windows.

Each record includes:

- `correlation_id`
- `rule`
- `confidence` (0.0 to 1.0)
- `window_start`
- `window_end`
- `event_ids[]`
- `source_types[]`
- `summary`
- `attributes`

## Validation rules

`autopack validate-pack` enforces:

1. required top-level files exist
2. `manifest.json` deserializes into canonical manifest schema
3. JSONL rows deserialize into canonical record schemas
4. stream row counts match `manifest` totals
5. `summary.md` is non-empty

## Compatibility notes

- JSON/JSONL are UTF-8 encoded
- timestamps use ISO-8601
- future Phase 1 increments may add source-derived artifacts and parquet outputs without breaking required core files
