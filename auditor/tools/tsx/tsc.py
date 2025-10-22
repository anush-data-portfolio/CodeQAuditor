# auditor/tools/tsc.py
from __future__ import annotations

import os
import re
import shlex
from pathlib import Path
from typing import List, Optional

from ..base import AuditTool, Finding, ToolRunResult
from .nodejs import NodeToolMixin

# tsc (pretty=false) diagnostic line:
_LINE = re.compile(
    r"""^(?P<file>.+?)\((?P<line>\d+),(?P<col>\d+)\):\s*
        (?P<sev>error|warning)\s*
        (?P<code>TS\d+):\s*(?P<msg>.*)$""",
    re.IGNORECASE | re.VERBOSE,
)

# Always-suppressed “missing module/defs” noise
DEFAULT_TSC_SUPPRESS: set[str] = {
    "TS2307",  # Cannot find module 'x'...
    "TS7016",  # Could not find a declaration file for module 'x'.
    "TS2688",  # Cannot find type definition file for 'x'.
}

# Offline basic (no node_modules): missing React/Node/JSX/Jest setup
OFFLINE_SUPPRESS_BASIC: set[str] = {
    "TS2580",  # 'process'
    "TS2503",  # namespace React
    "TS7026",  # JSX element implicitly any
    "TS17004", # JSX not enabled
    "TS2792",  # moduleResolution hint
    "TS5058",  # specified path does not exist (fresh tree)
}

# Offline aggressive: typical fallout from absent generics/ambient types
OFFLINE_SUPPRESS_AGGRESSIVE: set[str] = {
    *OFFLINE_SUPPRESS_BASIC,
    "TS7006",  # parameter implicitly any
    "TS7031",  # binding element implicitly any
    "TS2322",  # type not assignable to type (generic collapse)
    "TS2339",  # property does not exist on type
    "TS2741",  # Property 'children' is missing
    "TS18046", # 'x' is of type 'unknown'
    "TS2554",  # Expected N arguments, but got M
    "TS2559",  # Type has no properties in common
    "TS7022",  # 'x' implicitly has type 'any' because it does not have a type annotation
}

# Message patterns we often want to ignore offline
_OFFLINE_MSG_PATTERNS_BASIC = [
    re.compile(r"^Cannot find name\s+'(process|Buffer|global|require|module|__dirname|__filename)'\.", re.I),
    re.compile(r"^Cannot find name\s+'(describe|it|test|expect|beforeAll|beforeEach|afterAll|afterEach)'\.", re.I),
    re.compile(r"^Cannot find namespace\s+'React'\.", re.I),
    re.compile(r"JSX", re.I),
]
_OFFLINE_MSG_PATTERNS_AGGRESSIVE = [
    *(_OFFLINE_MSG_PATTERNS_BASIC),
    re.compile(r"implicitly has an 'any' type", re.I),
    re.compile(r"is not assignable to type", re.I),
    re.compile(r"does not exist on type", re.I),
    re.compile(r"is of type 'unknown'", re.I),
    re.compile(r"is missing in type", re.I),
]

_IGNORED_DIRS = {
    "node_modules", ".git", ".next", "dist", "build", "out", ".output",
    ".turbo", ".cache", ".pnpm", ".yarn", ".venv", "venv", "__pycache__",
}

class TscTool(AuditTool, NodeToolMixin):
    """
    TypeScript compiler (no emit) with multi-project and offline-aware filtering.

    • Discovers every subdir containing tsconfig.* and runs tsc per project.
    • Offline (auto/force): adds --noResolve and suppresses noise that disappears after npm install.
    • Tune suppression with offline_filter_level="basic" | "aggressive".
    """

    @property
    def name(self) -> str:
        return "tsc"

    def __init__(
        self,
        project: Optional[str] = None,               # force specific tsconfig filename
        no_emit: bool = True,
        pretty: bool = False,
        extra_args: Optional[List[str]] = None,
        suppress_codes: Optional[set[str]] = None,   # always suppressed
        package_version: Optional[str] = None,       # e.g., "^5"
        offline: Optional[bool] = None,              # None=auto (default), True, or False
        offline_filter_level: str = "aggressive",    # "basic" | "aggressive"
        **kw,
    ):
        super().__init__(**kw)
        self.project = project
        self.no_emit = no_emit
        self.pretty = pretty
        self.extra_args = extra_args or []
        self.suppress_codes = set(suppress_codes or DEFAULT_TSC_SUPPRESS)
        self.package_version = package_version
        self.offline = offline
        self.offline_filter_level = offline_filter_level.lower().strip()

    # ---------- command builder (single shell running all projects) ----------

    def build_cmd(self, path: str) -> List[str]:
        root = Path(path).resolve()
        projects = self._discover_ts_projects(root)
        if not projects:
            return ["/bin/bash", "-lc", "true"]

        npx_prefix = str(self._node_prefix())

        flags: List[str] = []
        if self.no_emit:
            flags.append("--noEmit")
        flags += ["--pretty", "true" if self.pretty else "false"]
        flags += ["--skipLibCheck"]
        flags += [shlex.quote(a) for a in self.extra_args]
        base_flag_str = " ".join(flags)

        pkg_flag = f"--package typescript@{self.package_version}" if self.package_version else ""

        entries: List[str] = []
        for (proj_dir, cfg) in projects:
            offline_flag = self._decide_offline_for_project(Path(proj_dir))
            entries.append(f"{proj_dir}:::{cfg}:::{1 if offline_flag else 0}")
        entries_str = " ".join(shlex.quote(e) for e in entries)

        script = f"""
set -euo pipefail
entries=({entries_str})
for entry in "${{entries[@]}}"; do
  proj="${{entry%%:::*}}"
  rest="${{entry#*:::}}"
  cfg="${{rest%%:::*}}"
  offline="${{rest##*:::}}"
  echo "##TSC-PROJ::$proj::OFFLINE=$offline"
  (
    cd "$proj"
    local_flags="{base_flag_str}"
    if [ "$offline" = "1" ]; then
      local_flags="$local_flags --noResolve"
    fi
    npx --yes --prefix {shlex.quote(npx_prefix)} {pkg_flag} tsc $local_flags -p "$cfg" || true
  )
done
"""
        return ["/bin/bash", "-lc", script]

    # ---------- discovery ----------

    def _discover_ts_projects(self, root: Path) -> List[tuple[str, str]]:
        root = root.resolve()
        projects: List[tuple[str, str]] = []

        def choose_tsconfig(d: Path) -> Optional[str]:
            if self.project and (d / self.project).exists():
                return self.project
            if (d / "tsconfig.json").exists():
                return "tsconfig.json"
            if (d / "tsconfig.build.json").exists():
                return "tsconfig.build.json"
            if (d / "tsconfig.base.json").exists():
                return "tsconfig.base.json"
            return None

        for dirpath, dirnames, _ in os.walk(root, topdown=True, followlinks=False):
            dirnames[:] = [dn for dn in dirnames if dn not in _IGNORED_DIRS and not dn.startswith(".git")]
            d = Path(dirpath)
            cfg = choose_tsconfig(d)
            if cfg:
                projects.append((str(d), cfg))

        seen = set()
        uniq: List[tuple[str, str]] = []
        for p, cfg in projects:
            key = (p, cfg)
            if key not in seen:
                seen.add(key)
                uniq.append((p, cfg))
        return uniq

    # ---------- offline decision ----------

    def _decide_offline_for_project(self, proj: Path) -> bool:
        if self.offline is True:
            return True
        if self.offline is False:
            return False
        cur = proj
        for _ in range(3):  # local or hoisted
            if (cur / "node_modules").exists():
                return False
            cur = cur.parent
        return True

    # ---------- parser ----------

    def parse(self, result: ToolRunResult) -> List[Finding]:
        top_root = Path(result.cwd).resolve()
        current_proj: Optional[Path] = None
        current_offline: bool = False
        findings: List[Finding] = []

        # pick filters
        level = "aggressive" if self.offline_filter_level not in {"basic","aggressive"} else self.offline_filter_level
        code_filter_basic = OFFLINE_SUPPRESS_BASIC
        code_filter_aggr  = OFFLINE_SUPPRESS_AGGRESSIVE
        msg_filter_basic  = _OFFLINE_MSG_PATTERNS_BASIC
        msg_filter_aggr   = _OFFLINE_MSG_PATTERNS_AGGRESSIVE

        for raw in (result.stdout or "").splitlines():
            line = raw.strip()
            if not line:
                continue

            if line.startswith("##TSC-PROJ::"):
                try:
                    _, rest = line.split("##TSC-PROJ::", 1)
                    proj_part, _, tail = rest.partition("::OFFLINE=")
                    current_proj = Path(proj_part).resolve()
                    current_offline = tail.strip() == "1"
                except Exception:
                    current_proj = None
                    current_offline = False
                continue

            m = _LINE.match(line)
            if not m:
                continue

            d = m.groupdict()
            code = (d.get("code") or "").strip()
            msg  = (d.get("msg") or "").strip()

            # Always-suppressed (both modes)
            if code in self.suppress_codes:
                continue

            # Extra offline suppressions
            if current_offline:
                if (level == "basic" and code in code_filter_basic) or \
                   (level == "aggressive" and code in code_filter_aggr):
                    continue
                # Message-pattern checks (guard TS2304 and others)
                patterns = msg_filter_basic if level == "basic" else msg_filter_aggr
                if any(p.search(msg) for p in patterns):
                    continue

            sev = (d.get("sev") or "error").lower()
            f = (d.get("file") or "").strip()

            file_path = Path(f)
            if not file_path.is_absolute() and current_proj is not None:
                file_path = (current_proj / file_path).resolve()

            try:
                f_rel = str(file_path.resolve().relative_to(top_root))
            except Exception:
                f_rel = str(file_path)

            findings.append(
                Finding(
                    name=f"tsc.{code}" if code else "tsc.diagnostic",
                    tool=self.name,
                    rule_id=code or None,
                    message=msg,
                    file=f_rel,
                    line=int(d.get("line") or 0) or None,
                    col=int(d.get("col") or 0) or None,
                    extra={"severity": sev, "offline": current_offline, "filter": level},
                    kind="issue",
                    category="type-check",
                    tags=["tsc", "typescript"] + ([code] if code else []),
                    metrics={"count": 1.0},
                )
            )

        return findings
