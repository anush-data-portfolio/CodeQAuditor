Awesome—let’s design this like we’re going to run it across 100k repos without babysitting. Here’s a pragmatic, fast, and safe architecture that (a) favors tools with machine-readable output, (b) scales horizontally, and (c) avoids per-repo setup as much as possible.

# High-level architecture

**Core idea:** a sandboxed worker runs a fixed set of OSS analyzers against a *read-only* checkout of a repo, normalizes results into a single schema (and SARIF export), and ships both raw and aggregated data to storage. A queue orchestrates millions of runs; you control CPU/RAM/time per tool.

```
auditor/
 ├─ auditor_cli/                # CLI & orchestration
 │   ├─ main.py
 │   ├─ scan_plan.py            # figures out what to run for a repo
 │   └─ exec.py                 # subprocess wrapper, timeouts, rlimits
 ├─ tools/                      # 1 file per tool (plugin architecture)
 │   ├─ ruff.py
 │   ├─ mypy.py   (or pyright.py)
 │   ├─ bandit.py
 │   ├─ radon.py
 │   ├─ semgrep.py
 │   ├─ pip_audit.py
 │   ├─ gitleaks.py
 │   └─ ...
 ├─ normalize/
 │   ├─ finding.py              # normalized Finding model (internal)
 │   ├─ sarif.py                # exporters → SARIF 2.1.0
 │   └─ metrics.py              # roll-ups & repo-level KPIs
 ├─ storage/
 │   ├─ writers.py              # parquet/jsonl/postgres
 │   └─ schema.sql              # tables if using Postgres
 ├─ runtime/
 │   ├─ sandbox.py              # container/cgroups, network off, tmpfs
 │   └─ fs.py                   # blob cache, checkout, sparse clone
 ├─ queue/
 │   ├─ local.py                # local ProcessPool executor
 │   └─ celery_or_ray.py        # distributed executor (pluggable)
 └─ auditor.yaml                # defaults (timeouts, memory, tool set)
```

---

## What we’ll run (OSS only)

### Python (fast, no project install)

* **Ruff** — linter + formatter; extremely fast; JSON output; also includes many Flake8/pycodestyle rules and Bandit ruleset coverage. ([GitHub][1])
* **Bandit** — security AST checks; JSON output. ([GitHub][2])
* **Radon** — complexity/maintainability metrics; JSON output. ([Radon][3])
* **Semgrep (CE)** — SAST with community rules; JSON & SARIF output. ([Semgrep][4])
* **pip-audit** — dependency CVEs from PyPI Advisory DB; JSON output. ([PyPI][5])
* **Gitleaks / TruffleHog** — secrets scanning; JSON output. ([GitHub][6])

### Python type checking (two modes)

* **Default (no install):** *Pyright* (or BasedPyright) for fast, repo-local type checking using typeshed and config; emits JSON via `--outputjson`. Great for “no env” scans. ([Microsoft GitHub][7])
* **Optional deep mode:** *mypy* with `--output json` when you *intentionally* resolve deps. (We’ll avoid this by default; see sandbox note below.) ([mypy][8])

### JS/TS (when you extend)

* **ESLint** (`--format json`, or SARIF via @microsoft/eslint-formatter-sarif). ([ESLint][9])
* **Prettier** (`--check`) to count formatting drift (don’t reformat). ([Prettier][10])
* **TypeScript** `tsc --noEmit` for type errors only. ([TypeScript][11])
* **npm audit --json** for dependency vulns. ([npm Docs][12])
* **jscpd** for duplication across many languages. ([GitHub][13])

> **Why this set?** Every tool above can run in a hermetic, read-only checkout and export machine-readable results; most can produce or be converted to SARIF, a cross-tool static-analysis standard that plays nicely with many platforms. ([OASIS Open][14])

---

## Don’t “pip install” user projects (by default)

Installing a random repo’s dependencies can execute arbitrary code during build (sdists/PEP-517), which is risky—even in isolated envs. Default policy: **no project install**. If you must, do it in an **offline, non-root container** with `--only-binary :all:` (skip sdists) and still assume risk. Prefer Pyright/mypy “missing imports ok” modes or stub generation. ([Phylum][15])

* Pyright JSON output and config support make it ideal for “no env” checks at scale. ([Basedpyright Docs][16])
* If you *do* use mypy, it has `--ignore-missing-imports`; use sparingly. ([mypy][17])

For dependency scans, use **pip-audit** (reads lock/requirements files) and **npm audit** for Node—no need to import or run project code. ([PyPI][5])

---

## Sandboxed execution (fast + safe)

* **Isolation:** Run each repo in a container (`--network=none`, read-only bind mount of the repo).
* **Resource limits:** `--cpus`, `--memory`, and per-tool **timeouts** (e.g., 120–300s).
* **No internet:** Prevent analyzers from fetching anything.
* **Temp workspace:** Use a tmpfs working dir; copy only needed files.

> If you need a “huge venv” for commonly-requested type stubs, use **uv** to keep a global cache and spin up ephemeral venvs quickly (it’s a very fast, Rust installer). ([GitHub][18])

---

## Repo ingestion (cheap I/O)

For massive scale, keep cloning lightweight:

* **Shallow & partial clones:** `git clone --depth=1 --filter=blob:none` and/or **sparse-checkout** to just the language directories you need. ([Git][19])
* Partial clone reduces transfer; fetch blobs on demand. ([The GitHub Blog][20])

Cache by **(host, repo, commit)** so identical commits never re-scan.

---

## Orchestration & scaling

* **Local:** `ProcessPoolExecutor` with `N` workers capped by CPU/GB.
* **Distributed (pick one):**

  * **Celery** (Redis/RabbitMQ broker) — stable task queue for millions of jobs. ([Celery Documentation][21])
  * **Ray** — simple primitives (tasks/actors) for parallel workers, resource-aware scheduling. ([Ray][22])

Workers are stateless; each pulls a scan job (repo, commit, tool set, limits), runs, and streams results.

---

## Data model & analytics

### Normalize everything

Internally, convert each tool’s output to a common **Finding** object:

```
Finding {
  repo, commit, language, tool, rule_id, severity, message,
  file, line, col, end_line, end_col,
  fingerprint, fixable, tags[], extra_json
}
```

Export a **SARIF 2.1.0** file per scan (one per language/toolset), so you can ingest elsewhere (e.g., GitHub code scanning). ([GitHub Docs][23])

### Storage strategy

* **Raw outputs:** write **NDJSON** per tool to object storage.
* **Queryable lake:** append **Parquet** + **DuckDB** for fast local OLAP (dev analytics, CI dashboards). DuckDB reads/writes Parquet natively and is blazing fast in-process. ([DuckDB][24])
* **Operational DB (optional):** **PostgreSQL** with a `findings` table (JSONB column for `extra_json`) + **GIN** indexes when you need flexible querying by nested keys. ([PostgreSQL][25])

**Tables (Postgres)**

* `repos(id, host, name, default_branch, first_seen, last_seen)`
* `scans(id, repo_id, commit, ts, toolset, status, duration_ms, cpu_sec, mem_peak_mb)`
* `files(id, scan_id, path, language, hash)`
* `findings(id, scan_id, file_id, tool, rule_id, severity, message, line, col, fingerprint, extra_json JSONB)`

  * Indexes: `(scan_id)`, `(tool, rule_id)`, `GIN(extra_json)`. ([PostgreSQL][26])

### KPIs you can compute

* Lint violation rate (per KLOC), security findings per severity, top recurring rules, mean complexity (Radon), duplication %, “format drift” count (Prettier/Ruff), secrets incidents, dependency CVE counts and severities.

---

## CLI UX (single entrypoint)

```
auditor scan <path|git-url> \
  --lang py \
  --tools ruff,bandit,radon,pyright,pip-audit,gitleaks,semgrep \
  --jobs 8 --mem-mb 2048 --timeout-s 300 \
  --out ./out --export sarif,jsonl,parquet
```

* **Jobs** = per-repo parallelism (tool fan-out is internal & bounded).
* **Time/Mem limits** apply per tool.
* **Config file** (`auditor.yaml`) overrides defaults tool-by-tool.

---

## Per-tool invocation & parsing (examples)

* **Ruff:** `ruff check . --format json` (+ optionally `ruff format --check` for drift count). ([GitHub][1])
* **Bandit:** `bandit -r . -f json`. ([GitHub][2])
* **Radon:** `radon cc -s -j .` and `radon mi -j .` for complexity & maintainability. ([Radon][3])
* **Semgrep:** `semgrep scan --config p/ci --json` (or `--sarif`). ([Semgrep][4])
* **pip-audit:** `pip-audit -r requirements*.txt -f json`. ([PyPI][5])
* **Pyright:** `pyright --outputjson`. ([Basedpyright Docs][16])
* **Gitleaks:** `gitleaks detect --no-git --source . --report-format=json`. ([GitHub][6])

JS/TS later:

* **ESLint:** `eslint . -f json` (or `-f @microsoft/eslint-formatter-sarif`). ([ESLint][9])
* **Prettier:** `prettier . --check` (collect files listed as different). ([Prettier][10])
* **TS:** `tsc --noEmit`. ([TypeScript][11])
* **npm audit:** `npm audit --json`. ([npm Docs][12])
* **jscpd:** `jscpd --reporters json`. ([GitHub][13])

---

## Performance & scale notes

* **No per-repo installs by default** keeps runs deterministic and fast.
* **Fan-out carefully:** run fast analyzers first (Ruff/Radon/Gitleaks), then slower ones (Semgrep), all within the same sandbox with strict timeouts.
* **Content-addressed cache:** skip rescans of identical `(repo, commit)` and reuse raw outputs if unchanged.
* **Git tricks:** sparse/partial clone to minimize I/O and disk. ([Git][27])
* **Executor choice:** Celery for a classic, durable queue; Ray if you want auto resource scheduling and easy horizontal scale with CPU quotas. ([Celery Documentation][21])

---

## Security posture

* **Never execute project code.** If you must install for deeper typing: do it in a throwaway container with `--network=none`, non-root user, strict `ulimit`, and prefer `--only-binary :all:`; otherwise skip packages that require building from source (sdists can run arbitrary code). ([Phylum][15])
* **Secrets scanners** run with history off by default (`--no-git`) unless you explicitly allow scanning history (heavier). ([GitHub][6])

---

## Outputs & interoperability

* **Raw:** `out/<tool>.jsonl` per tool.
* **Normalized:** `out/findings.parquet` (+ aggregated metrics `.parquet`).
* **SARIF:** `out/auditor.sarif` for uploads to GitHub / other viewers. ([GitHub Docs][23])

---

## Minimal DB schema (Postgres)

```sql
CREATE TABLE repos (
  id BIGSERIAL PRIMARY KEY,
  host TEXT NOT NULL, name TEXT NOT NULL,
  default_branch TEXT, first_seen TIMESTAMPTZ, last_seen TIMESTAMPTZ
);

CREATE TABLE scans (
  id BIGSERIAL PRIMARY KEY,
  repo_id BIGINT REFERENCES repos(id),
  commit TEXT NOT NULL, ts TIMESTAMPTZ NOT NULL,
  toolset TEXT NOT NULL, status TEXT NOT NULL,
  duration_ms INT, cpu_sec INT, mem_peak_mb INT
);

CREATE TABLE findings (
  id BIGSERIAL PRIMARY KEY,
  scan_id BIGINT REFERENCES scans(id),
  file_path TEXT, language TEXT,
  tool TEXT, rule_id TEXT, severity TEXT,
  message TEXT, line INT, col INT,
  fingerprint TEXT,
  extra_json JSONB
);
-- Optional JSONB index for flexible querying:
CREATE INDEX findings_extra_gin ON findings USING GIN (extra_json);
```

(Use DuckDB/Parquet instead of Postgres if you prefer in-process OLAP and cheap ops.) ([DuckDB][24])

---

## Config example (`auditor.yaml`)

```yaml
defaults:
  timeout_s: 300
  mem_mb: 2048
  cpus: 1
  network: false

python:
  tools: [ruff, bandit, radon, pyright, pip-audit, gitleaks, semgrep]
  pyright:
    config: pyrightconfig.json
  mypy:
    enabled: false
    args: ["--output", "json", "--ignore-missing-imports"]

javascript:
  tools: [eslint, prettier, tsc, npm-audit, jscpd]
  eslint:
    format: json
    sarif_formatter: "@microsoft/eslint-formatter-sarif"

storage:
  raw_dir: "out/raw"
  parquet_dir: "out/parquet"
  sarif_path: "out/auditor.sarif"
  postgres_dsn: null   # fill to enable Postgres

queue:
  mode: "local"        # or "celery" or "ray"
```

---

## What you get on day one

* **Fast scans** that don’t need per-repo setup.
* **One JSON/Parquet/SARIF output** you can slice by repo, tool, file, rule, severity, complexity, duplication, secrets, and CVEs.
* **A switch to go deeper** (Pyright→mypy+optional deps) with explicit sandboxing.

If you’d like, I can turn this into a small Python skeleton (CLI + plugin base + two tools wired up) and a Dockerfile that enforces the sandbox and resource limits.

[1]: https://github.com/astral-sh/ruff?utm_source=chatgpt.com "astral-sh/ruff: An extremely fast Python linter and code ..."
[2]: https://github.com/PyCQA/bandit?utm_source=chatgpt.com "PyCQA/bandit: Bandit is a tool designed to find common ..."
[3]: https://radon.readthedocs.io/en/latest/commandline.html?utm_source=chatgpt.com "Command-line Usage — Radon 4.1.0 documentation"
[4]: https://semgrep.dev/docs/cli-reference?utm_source=chatgpt.com "CLI reference"
[5]: https://pypi.org/project/pip-audit/?utm_source=chatgpt.com "pip-audit"
[6]: https://github.com/gitleaks/gitleaks?utm_source=chatgpt.com "Find secrets with Gitleaks"
[7]: https://microsoft.github.io/pyright/?utm_source=chatgpt.com "Pyright - Microsoft Open Source"
[8]: https://mypy.readthedocs.io/en/latest/command_line.html?highlight=json&utm_source=chatgpt.com "The mypy command line - MyPy documentation - Read the Docs"
[9]: https://eslint.org/docs/latest/use/command-line-interface?utm_source=chatgpt.com "Command Line Interface Reference"
[10]: https://prettier.io/docs/cli?utm_source=chatgpt.com "CLI"
[11]: https://www.typescriptlang.org/docs/handbook/compiler-options.html?utm_source=chatgpt.com "Documentation - tsc CLI Options"
[12]: https://docs.npmjs.com/cli/v8/commands/npm-audit/?utm_source=chatgpt.com "npm-audit"
[13]: https://github.com/kucherenko/jscpd?utm_source=chatgpt.com "kucherenko/jscpd: Copy/paste detector for programming ..."
[14]: https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=sarif&utm_source=chatgpt.com "OASIS Static Analysis Results Interchange Format (SARIF) ..."
[15]: https://blog.phylum.io/python-package-installation-attacks/?utm_source=chatgpt.com "Python Package Installation Attacks"
[16]: https://docs.basedpyright.com/v1.22.1/configuration/command-line/?utm_source=chatgpt.com "Command line"
[17]: https://mypy.readthedocs.io/en/stable/running_mypy.html?utm_source=chatgpt.com "Running mypy and managing imports"
[18]: https://github.com/astral-sh/uv?utm_source=chatgpt.com "astral-sh/uv: An extremely fast Python package and project ..."
[19]: https://git-scm.com/docs/git-clone?utm_source=chatgpt.com "Git - git-clone Documentation"
[20]: https://github.blog/open-source/git/get-up-to-speed-with-partial-clone-and-shallow-clone/?utm_source=chatgpt.com "Get up to speed with partial clone and shallow clone"
[21]: https://docs.celeryq.dev/?utm_source=chatgpt.com "Celery - Distributed Task Queue — Celery 5.5.3 documentation"
[22]: https://docs.ray.io/en/latest/ray-core/walkthrough.html?utm_source=chatgpt.com "What's Ray Core? — Ray 2.50.0 - Ray Docs"
[23]: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning?utm_source=chatgpt.com "SARIF support for code scanning"
[24]: https://duckdb.org/?utm_source=chatgpt.com "DuckDB – An in-process SQL OLAP database management ..."
[25]: https://www.postgresql.org/docs/current/datatype-json.html?utm_source=chatgpt.com "Documentation: 18: 8.14. JSON Types"
[26]: https://www.postgresql.org/docs/current/gin.html?utm_source=chatgpt.com "Documentation: 18: 65.4. GIN Indexes"
[27]: https://git-scm.com/docs/git-sparse-checkout?utm_source=chatgpt.com "git-sparse-checkout Documentation"
