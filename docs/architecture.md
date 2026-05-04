# AutoPack Architecture (Phase 1 Initial Slice)

## Design goals

- Deterministic-first preprocessing
- Evidence-centric outputs over prose-only summaries
- CLI as the product center
- Typed and testable code

## Current module map

### `autopack.cli`

#### CLI purpose

- Provide user-facing command entrypoints

#### CLI inputs

- CLI arguments for source files and pack paths

#### CLI outputs

- Exit codes and command-line status output

#### CLI invariants

- Commands return non-zero on validation/build failure
- `build`, `summarize`, and `validate-pack` are always available

#### CLI extension points

- Future commands (`explain`, `compare`) can be added without changing pack core

### `autopack.schema`

#### Schema purpose

- Canonical typed schema for all pack records

#### Schema inputs

- Python values or parsed JSON dictionaries

#### Schema outputs

- Validated dataclass instances and serialized dictionaries

#### Schema invariants

- Required identifiers and timestamps are present
- Confidence and time-window constraints are enforced

#### Schema extension points

- Additional schema fields for parser/decoder stages and richer metadata

### `autopack.pack.writer`

#### Writer purpose

- Materialize deterministic investigation packs to disk

#### Writer inputs

- Typed manifest, timeline events, anomalies, correlations, summary markdown

#### Writer outputs

- Complete pack directory with JSON/JSONL/Markdown artifacts

#### Writer invariants

- Required pack artifacts are always written together
- Evidence helper files are generated deterministically from structured records

#### Writer extension points

- Additional pack artifacts (e.g., source-derived parsed files, parquet outputs)

### `autopack.pack.validator`

#### Validator purpose

- Enforce pack integrity and schema correctness

#### Validator inputs

- Pack directory path

#### Validator outputs

- `PackValidationResult` (valid/errors/warnings/manifest)

#### Validator invariants

- Required files must exist
- JSONL rows must deserialize into canonical models
- Manifest aggregate counts must match stream row counts

#### Validator extension points

- Additional strict checks for source hashes, parquet schemas, benchmark thresholds

### `autopack.pack.pipeline`

#### Pipeline purpose

- Deterministic build orchestration for Phase 1 CLI

#### Pipeline inputs

- DLT + bus trace + DBC (+ optional syslog/test inputs)

#### Pipeline outputs

- Normalized events, anomaly windows, temporal correlations, and final pack

#### Pipeline invariants

- One of BLF/ASC is required with DLT and DBC
- Event IDs and session IDs are deterministic hashes
- No LLM/embeddings/reranker usage

#### Pipeline extension points

- Replace line-based ingestion with protocol-aware parsers
- Add true DBC decode and multi-source timestamp alignment

## Runtime flow

1. CLI parses command arguments
2. Build pipeline validates source arguments
3. Source files are ingested into normalized events
4. Deterministic anomaly grouping and temporal correlation run
5. Pack writer emits machine-readable and human-readable artifacts
6. Validator can verify structural and semantic integrity

## Tradeoffs in this initial slice

- Prioritizes deterministic pack contract and CLI usability before deep protocol parsers
- Uses lightweight line-based ingestion until dedicated DLT/BLF/ASC adapters are implemented
- Keeps dependencies minimal to reduce setup friction and improve reproducibility
