# CodeQAuditor

Repo-agnostic static-analysis runner for **Python** and **JS/TS/TSX** codebases.
You point it at a repo path; it runs a curated set of analyzers and emits normalized **Findings** that share a single schema (`kind`, `category`, `tags`, `metrics`, locations, etc.). Tools are installed **once** in this project and reused across any number of target repos — no per-repo installs.

---

## Highlights

* **One toolchain, many repos**: Python tools live in a single virtualenv; JS/TS tools live in a single `node_modules` folder. You scan 500k repos without installing into each.
* **Batteries included**:

  * Python: `ruff`, `mypy`, `pyright`, `radon` (CC/MI/Halstead/LOC), `bandit`, `semgrep` (optional), `vulture`, `gitleaks`, `jscpd`.
  * JS/TS/TSX: `eslint`, `@typescript-eslint/*`, `madge` (cycles), `depcheck` (unused deps), `ts-prune`, `tsc` (typecheck only), `@biomejs/biome`, `jscpd`.
* **Noise-reduced defaults**: Focus on **code quality** (complexity, style, correctness); e.g., ESLint suppresses unresolved-import churn by default.
* **Unified Finding schema** with `kind` (`issue|analysis|summary`), `category` (e.g., `security`, `complexity`, `architecture`, `lint`), free-form `tags`, and numeric `metrics`.
* **Portable configs** (in `auditor/`) that analyzers can reuse when a target repo has none.

---

## Repo layout (brief)

```
auditor/
  auditor_cli/           # simple CLI runner
  normalize/             # Finding <-> SARIF/metrics helpers
  runtime/               # fs helpers & sandbox utilities
  storage/               # writers (db/files)
  tools/
    base.py              # AuditTool/Finding/ToolRunResult
    python/              # py analyzers
    tsx/                 # js/ts analyzers (NodeToolMixin, etc.)
auditor/auditor.yaml     # (optional) scan plan / defaults
quick_probe.py           # tiny demo runner
requirements.txt         # Python deps for this project
```

---

## Prerequisites

* **Python** 3.12+ (recommended; works on 3.10+ for most tools)
* **Node.js** 18+ (20+ recommended) and **npm**

---

## One-time setup

### 1) Python environment

```bash
cd /home/you/CodeQAuditor
python3 -m venv .auditenv
source .auditenv/bin/activate

pip install -U pip
pip install -r requirements.txt
```

### 2) Central JS/TS toolchain (installed **once**)

```bash
cd auditor
npm init -y
npm i -D \
  eslint @eslint/js typescript @typescript-eslint/parser @typescript-eslint/eslint-plugin \
  eslint-plugin-react eslint-plugin-react-hooks eslint-plugin-jsx-a11y \
  eslint-plugin-unicorn eslint-plugin-sonarjs \
  madge depcheck ts-prune @biomejs/biome jscpd
```

Export a helper so analyzers can find the local binaries:

```bash
export AUDITOR_NODE_BIN="$(pwd)/node_modules/.bin"
# consider putting this in your shell rc or your launcher script
```

---

## Portable configs (live inside `auditor/`)

> Use these when a target repo lacks its own config, or when you want consistent rules everywhere.

### ESLint (flat config)

`auditor/eslint.config.mjs`

```js
import js from "@eslint/js";
import tseslint from "@typescript-eslint/eslint-plugin";
import tsParser from "@typescript-eslint/parser";
import react from "eslint-plugin-react";
import reactHooks from "eslint-plugin-react-hooks";
import a11y from "eslint-plugin-jsx-a11y";
import unicorn from "eslint-plugin-unicorn";
import sonarjs from "eslint-plugin-sonarjs";

export default [
  js.configs.recommended,
  {
    files: ["**/*.{js,jsx,ts,tsx}"],
    languageOptions: {
      parser: tsParser,
      parserOptions: { ecmaVersion: "latest", sourceType: "module", project: false },
    },
    plugins: {
      "@typescript-eslint": tseslint,
      react, "react-hooks": reactHooks, "jsx-a11y": a11y, unicorn, sonarjs,
    },
    rules: {
      // Focus on code quality; suppress import-churn noise:
      "import/no-unresolved": "off",
      "node/no-missing-import": "off",
      "n/no-missing-import": "off",
      "n/no-missing-require": "off",
      "node/no-missing-require": "off",

      "no-console": "warn",
      "no-unused-vars": "off",
      "@typescript-eslint/no-unused-vars": ["warn", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],

      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "warn",
      "jsx-a11y/alt-text": "warn",
      "unicorn/prefer-optional-catch-binding": "error",
      "sonarjs/cognitive-complexity": ["warn", 15],
    },
    settings: { react: { version: "detect" } },
  },
];
```

### TypeScript config (standalone)

`auditor/tsconfig.standalone.json`

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "jsx": "react-jsx",
    "allowJs": true,
    "checkJs": false,
    "skipLibCheck": true,
    "strict": true,
    "noEmit": true,
    "resolveJsonModule": true,
    "esModuleInterop": true
  },
  "include": ["**/*.{ts,tsx,js,jsx}"],
  "exclude": ["**/node_modules", "**/dist", "**/build", "**/.next"]
}
```

> Your JS/TS tools use these when the target repo doesn’t provide its own config, or you pass them explicitly.

---

## Running a scan

### Quick demo (single repo)

```bash
# ensure envs are set
source .auditenv/bin/activate
export AUDITOR_NODE_BIN="/home/you/CodeQAuditor/auditor/node_modules/.bin"

python3 quick_probe.py  # edit this file to point at any repo you want
```

`quick_probe.py` typically looks like:

```python
from auditor.tools.tsx.eslint import EslintTool
from auditor.tools.tsx.tsc import TscTool
from auditor.tools.python.radon import RadonTool
from pathlib import Path

repo = Path("/path/to/target/repo")

tools = [
  RadonTool(),                        # Python complexity/MI/Halstead/LOC
  EslintTool(config_path="auditor/eslint.config.mjs"),
  TscTool(project="auditor/tsconfig.standalone.json"),
  # add others: MadgeTool(), DepcheckTool(), PyrightTool(), etc.
]

for t in tools:
    findings, run = t.audit(repo)
    print(t.name, len(findings), run.returncode)
```

### CLI runner

There’s a simple CLI in `auditor/auditor_cli/main.py`. A typical pattern:

```bash
python -m auditor.auditor_cli.main \
  --repo /path/to/repo \
  --tools tsx:eslint,tsx:tsc,tsx:madge,python:radon,python:ruff \
  --eslint-config auditor/eslint.config.mjs \
  --tsc-project auditor/tsconfig.standalone.json \
  --out findings.json
```

*(Adjust flags to match your CLI’s current argument names.)*

---

## What “Finding” looks like

All tools normalize into the same shape:

```python
@dataclass
class Finding:
    name: str                 # "eslint.no-unused-vars"
    tool: str                 # "eslint"
    rule_id: Optional[str]    # "no-unused-vars"
    message: str              # human-readable message
    file: Optional[str]       # repo-relative path
    line: Optional[int]
    col: Optional[int]
    end_line: Optional[int]
    end_col: Optional[int]
    fingerprint: Optional[str]
    extra: Optional[Dict[str, Any]]

    # classification & metrics
    kind: str = "issue"       # "issue" | "analysis" | "summary"
    category: Optional[str] = None   # "lint" | "security" | "complexity" | ...
    tags: Optional[List[str]] = None # free-form labels
    metrics: Optional[Dict[str, float]] = None  # numeric metrics
```

Examples:

* Radon CC blocks → `kind="analysis"`, `category="complexity"`, `metrics={"cc": 8}`.
* ESLint diagnostics → `kind="issue"`, `category="lint"/"types"/"a11y"`, `metrics={"count": 1}`.
* Madge cycle → `kind="issue"`, `category="architecture"`, `metrics={"cycle_length": 4}`.

You can serialize these to JSON or SARIF using helpers under `auditor/normalize/`.

---

## Tool catalogue (default posture)

**Python**

* `ruff` — fast lint/format. Category: `lint` / `style`.
* `mypy` — type checking + coverage metrics (file + repo). Category: `type-check`.
* `pyright` — fast type checking (env-noise suppressed). Category: `type-check`.
* `radon` — CC/MI/Halstead/LOC per file. Category: `complexity` / `analysis`.
* `bandit` — security heuristics. Category: `security`.
* `semgrep` (optional) — patterns/queries. Category: `security` / `bug-risk`.
* `vulture` — dead code. Category: `deadcode`.
* `gitleaks` — secrets. Category: `secrets`.
* `jscpd` — duplication. Category: `duplication`.

**JS/TS/TSX**

* `eslint` — quality-focused (import-noise suppressed). Category: `lint` / `types` / `a11y`.
* `tsc` — no-emit typecheck. Category: `type-check`.
* `madge` — circular deps + orphans. Category: `architecture` / `deadcode`.
* `depcheck` — unused/missing deps (signal only; noisy across monorepos). Category: `deps`.
* `ts-prune` — unused exports. Category: `deadcode`.
* `biome` — formatter/lints (fast). Category: `lint`.
* `jscpd` — duplication. Category: `duplication`.

---

## Scaling to many repos

* **Reuse environments**:

  * Python: keep `.auditenv` active; install once.
  * Node: keep `auditor/node_modules`; set `AUDITOR_NODE_BIN` once.
* **No per-repo installs**: tools run in “read-only” mode against repo paths.
* **Timeouts**: each tool inherits a default timeout (300s). Tweak via constructor.
* **Parallelism**: run multiple scans with your queue in `auditor/queue/` (local, Celery/Ray stubs).
* **Disk considerations**: mypy uses a temp sqlite cache per run; other tools are mostly stateless.

---

## Troubleshooting

* **`FileNotFoundError: 'eslint'` or `'tsc'`**
  Ensure `AUDITOR_NODE_BIN` is set and points to `auditor/node_modules/.bin`. Confirm the binaries exist there.

  ```bash
  ls $AUDITOR_NODE_BIN/eslint $AUDITOR_NODE_BIN/tsc
  ```

* **ESLint `ERR_MODULE_NOT_FOUND` for `@eslint/js` / `@eslint/eslintrc`**
  Install ESLint + plugins **next to your config file** (`auditor/`). Your tools should run the binary from that same folder (see `NodeToolMixin`) and pass `-c auditor/eslint.config.mjs`.

* **TSC “Project not found”**
  Provide `-p auditor/tsconfig.standalone.json` (or a repo’s own `tsconfig.json`).

* **Empty JSON from a tool**
  Usually means the tool crashed before emitting JSON. Inspect `ToolRunResult.stderr` and fix the missing module/config.

---

## Extending with a new tool

1. Create `auditor/tools/{python|tsx}/mytool.py`.
2. Subclass `AuditTool`, implement `name`, `build_cmd()` **or** `audit()`, and `parse()`.
3. Emit `Finding` objects. Populate `kind/category/tags/metrics` thoughtfully.
4. Wire it into your CLI / scan plan.

Template:

```python
from ..base import AuditTool, Finding

class MyTool(AuditTool):
    @property
    def name(self): return "mytool"

    def build_cmd(self, path: str) -> list[str]:
        return ["mytool", "--json", "."]

    def parse(self, result) -> list[Finding]:
        data = result.parsed_json or []
        findings = []
        # ...build Finding(...)
        return findings
```

---

## Recommended run profiles

**Python-heavy repo**

```bash
python -m auditor.auditor_cli.main \
  --repo /path \
  --tools python:ruff,python:radon,python:mypy,python:pyright,python:jscpd,python:bandit
```

**Next.js/React repo**

```bash
python -m auditor.auditor_cli.main \
  --repo /path \
  --tools tsx:eslint,tsx:tsc,tsx:madge,tsx:ts-prune,tsx:jscpd \
  --eslint-config auditor/eslint.config.mjs \
  --tsc-project auditor/tsconfig.standalone.json
```

---

## Notes

* This project doesn’t enforce severity; **you decide** how to interpret `category/tags/metrics` downstream.
* Many tools can be noisy across polyrepos/monorepos — defaults here trend conservative to keep signal high.

---

Happy auditing!
