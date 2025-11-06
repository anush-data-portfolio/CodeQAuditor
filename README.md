# CodeQAuditor

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

**CodeQAuditor** is a comprehensive, production-ready static analysis orchestration platform for Python and JavaScript/TypeScript codebases. It provides a unified interface to run multiple static analysis tools, normalize their outputs, and store results in a structured database for analysis and reporting.

## Features

- **Multi-Tool Support**: Integrates Bandit, Mypy, Radon, Vulture, ESLint, and Semgrep
- **Parallel Execution**: Run multiple tools simultaneously for faster analysis
- **Unified Data Model**: Normalized ORM models for consistent result storage
- **Interactive Dashboard**: Web-based visualization of analysis results
- **Extensible Architecture**: Easy to add new tools and parsers
- **Production Ready**: Comprehensive error handling, logging, and configuration management
- **Export Capabilities**: Export results to CSV and JSON formats


Project snapshot
----------------

- **CLI entry point**: `python -m auditor` exposes the Typer-based interface defined in `auditor/cli.py`.
- **Services**: `auditor/services/orchestrator.py` runs tools in parallel subprocesses, converts raw results through `parsetomodels`, and writes scan rows via the DB helpers.
- **Database layer**: `auditor/db/connection.py`, `auditor/db/utils.py`, and `auditor/db/seed.py` manage the SQLite engine, WAL configuration, session scope, and persistence helpers such as `save_scan_and_rows`.
- **Models**: `auditor/models/orm.py` contains the SQLAlchemy metadata; conversion helpers live in `auditor/models/schema.py` and the specialised parser modules.
- **Tool wrappers**: `auditor/tools/...` expose `audit(target) -> ToolRunResult` contracts so every analyzer can be launched either directly or through the CLI.
- **Main module**: `auditor/main.py` invokes the CLI application, enabling `python -m auditor` usage.


Supported analyzers
-------------------

| Tool      | Language focus | Purpose | Output handling |
|-----------|----------------|---------|-----------------|
| Bandit    | Python         | Security linting for common vulnerabilities | Parses `run.parsed_json["results"]` into `BanditResult` rows |
| Mypy      | Python         | Static type checking (stdout NDJSON) | Converts stdout text into `MypyResult` rows |
| Radon     | Python         | Complexity, maintainability, Halstead, raw metrics | Aggregates the combined JSON bundle into `RadonResult` rows |
| Vulture   | Python         | Dead code detection | Parses stdout lines into `VultureResult` rows, honouring a minimum confidence threshold |
| ESLint    | JS/TS/JSX/TSX  | Style and quality linting using the central rule pack | Builds scan, file, and issue rows through `eslint_rows_to_models` |

Each tool wrapper inherits from `AuditTool` or `CommandAuditTool` and returns a `ToolRunResult` with the fields required by the parsing helpers (`cmd`, `cwd`, `returncode`, `duration_s`, `stdout`, `stderr`, `parsed_json`).


Database workflow
-----------------

1. `python -m auditor seed-db` seeds the SQLite database (default path `db/auditor.sqlite3`), enabling WAL mode and creating tables from `auditor.models.orm.Base`.
2. Every tool run produces one scan row (`ScanMetadata`) and zero or more result rows stored in the corresponding table (`BanditResult`, `MypyResult`, `RadonResult`, `VultureResult`, `EslintResult`).
3. The helper `save_scan_and_rows(Base, scan_row, result_rows)` attaches the objects to a fresh session, flushes once, and reports counts to the CLI.
4. Environment overrides: set `AUDITORDBPATH` to relocate the database file, and `AUDITORDBECHO=1` to enable SQL logging.


CLI guide
---------

Assuming Python 3.10+ is available and the necessary analyzers (Bandit, Mypy, Radon, Vulture, ESLint plus their Node dependencies) are installed in the host environment:

- Initialise the database: run `python -m auditor seed-db`.
- Execute a single tool: `python -m auditor run-tool <tool> <target> [--json-out PATH]` where `<tool>` is one of `bandit`, `mypy`, `radon`, `vulture`, or `eslint`. The command emits a JSON payload with stdout, stderr, exit code, and parsed JSON data; optionally write it to a file via `--json-out`.
- Run a full audit: `python -m auditor audit <path>` launches the default tool suite in parallel using subprocesses, converts each result via the schema helpers, and persists everything to SQLite.
- Filter the tools: append `--tool bandit --tool radon` to restrict the run. `--jobs` caps parallelism; `--stop-on-error` aborts on the first failing analyzer.
- Workspace mode: add `--multi` to treat `<path>` as a root directory. The orchestrator inspects the first-level subdirectories (excluding `.git`, `node_modules`, `.venv`, `venv`, `__pycache__`, `dist`, `build`, `.mypy_cache`) and audits each project sequentially while keeping per-project tool execution parallelised.


Result parsing
--------------

A shared function `parsetomodels(result: ToolRunResult)` resolves the correct converter based on `result.tool`:

- Bandit → `bandit_json_to_models(result.parsed_json.get("results", []), cwd=result.cwd)`
- Mypy → `mypy_ndjson_to_models(result.stdout.strip(), cwd=result.cwd)`
- Radon → `radon_to_models(result.parsed_json or {}, cwd=result.cwd)`
- Vulture → `vulture_text_to_models(result.stdout or "", cwd=result.cwd, min_confidence=50)`
- ESLint → `eslint_rows_to_models(run_shim)` where the shim mirrors the run attributes (`parsed_json`, `stdout`, `stderr`, `cwd`, `returncode`, `duration_s`, `cmd`).

Every converter returns a `(scan_row, rows)` tuple compatible with `save_scan_and_rows`.


Extending the suite
-------------------

- Implement a new tool wrapper deriving from `AuditTool` and returning `ToolRunResult`.
- Add the factory to `TOOL_FACTORIES` in `auditor/services/orchestrator.py` and supply the appropriate branch in `parsetomodels`.
- Provide a converter in `auditor/models/parsers` that maps the tool’s raw output to ORM objects.
- Update the CLI’s default tool list if the new analyzer should run during `audit`.


Troubleshooting tips
--------------------

- Missing analyzers: the CLI emits warnings when a subprocess exits non-zero. Use `--stop-on-error` to fail fast during experimentation.
- ESLint dependencies: ensure the central Node toolchain includes the plugins referenced by `auditor/node_tools` (unified installation under `script_tool_cache` or `node_tools`).
- Large workspaces: use `--jobs` to balance parallelism with CPU utilisation. SQLite operates in WAL mode, so concurrent writes from sequential projects remain safe.
- Logs: CLI commands print per-tool row counts and any stderr captured from subprocesses for quick diagnostics.


Status
------

The repository now ships with a functional end-to-end auditing pipeline: database seeding, tool orchestration, result normalisation, and persistence are all handled by the new CLI stack. Refer to `tester.py` for a scripted example that instantiates the tools directly, parses their output, and inspects the generated ORM objects.
