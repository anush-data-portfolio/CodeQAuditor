## Quick orientation for AI coding agents

This project is a static-analysis orchestration platform (Python 3.10+). Use these notes to be productive quickly and avoid incorrect assumptions.

- Big picture
  - The CLI app is the primary surface: run with `python -m auditor` (entry in `auditor/main.py`). See commands in `auditor/auditor_cli/cli.py`.
  - Orchestrator (`auditor/application/orchestrator.py`) is the core: it instantiates tool classes from `auditor/infra/tools/*`, runs them (orchestrates subprocesses), converts outputs via `parsetomodels` and persists via `auditor.infra.db.utils.save_scan_and_rows`.
  - Data model is SQLAlchemy-based in `auditor/core/models/orm.py`. Most results inherit from `ResultsBase` which computes a deterministic `pk` via `build_pk()` prior to insert.

- Key developer workflows & commands
  - Seed DB: `python -m auditor seed-db` (uses `CONFIG.database_url`, configured in `config.py` via env vars).
  - Run full audit of a path: `python -m auditor audit /path/to/project` (supports `--tool`, `--jobs`, `--parallel`, `--multi`, `--stop-on-error`).
  - Run single tool: `python -m auditor run-tool <tool> <target> --json-out <path>` (the orchestrator also calls this command when spawning subprocesses).
  - Export findings: `python -m auditor export --output-path ./out` or `--root <folder-name>` to select a root preserved in DB.

- Configuration & environment
  - `config.py` loads these required env vars: `DATABASE_URL` (SQLite URL like `sqlite:////abs/path/to/db`), `GITIGNORE_PATH`. Optional `NODE_TOOLS_CACHE` controls where Node tool packs are stored (defaults to `node_tools/`).
  - Node/JS toolchain: `auditor/infra/tools/eslint` and the `node_tools/` folder contain Node configs and central rule packs; treat Node deps as external — the repo expects them to be present.

- Project-specific patterns & conventions
  - Tool wrapper contract: create classes under `auditor/infra/tools/<tool>/base.py` that return a `ToolRunResult` (or a (findings, ToolRunResult) tuple). The orchestrator uses `TOOL_FACTORIES` to instantiate by name.
  - Parsing: normalize outputs in `auditor/core/models/schema.py` (functions like `bandit_json_to_models`, `mypy_ndjson_to_models`, `eslint_rows_to_models`), and return `(scan_row, rows)` pairs for `save_scan_and_rows`.
  - `ResultsBase.build_pk()`: PK includes table name + project root + relpath + tool-specific keys. Do not change PK shape lightly — it is relied on for deduping.
  - Radon is treated as metrics (RadonResult) and typically excluded from issue exports; ESLint parsing may use a radon bundle (see `eslint_rows_to_models(..., radon_bundle=...)`).

- How to add a new analyzer (concrete steps)
  1. Add tool wrapper under `auditor/infra/tools/<name>/` implementing `audit(target) -> ToolRunResult`.
 2. Add parser that maps raw output to ORM rows under `auditor/core/models/parsers` (or update `schema` functions) and return `(scan_row, rows)`.
 3. Register the tool in `TOOL_FACTORIES` in `auditor/application/orchestrator.py` and add a branch in `parse_to_models` / `parsetomodels`.
 4. Update CLI defaults if the tool should run as part of `audit`.

- Integration points & gotchas
  - Database: uses SQLAlchemy engine created from `CONFIG.database_url` (see `auditor/infra/db/connection.py`). The project expects SQLite and `connect_args={'check_same_thread': False}`.
  - Concurrency: orchestrator supports thread/process pool options; CLI exposes `--jobs` and `--parallel` flags. When testing, use small `--jobs` to reduce resource contention.
  - Subprocess path: the orchestrator spawns `python -m auditor run-tool ...` for subprocess runs — changes to CLI arguments must preserve this invocation shape.
  - Exports: `auditor/application/extractor.py` exposes `extract_findings_to_json` and `metabob_to_auditor` for downstream consumers.

- Files you will reference frequently
  - `auditor/auditor_cli/cli.py` (commands, options, export behavior)
  - `auditor/application/orchestrator.py` (TOOL_FACTORIES, orchestration, parse_to_models)
  - `auditor/core/models/orm.py` (DB schema, ResultsBase pk behavior)
  - `auditor/core/models/schema.py` (parsers / converters)
  - `auditor/infra/tools/*` (tool implementations)
  - `config.py` (env-driven config shape)

If any of the above sections are unclear or you want more examples (e.g., a minimal new-tool scaffold), tell me which area to expand and I will iterate.
