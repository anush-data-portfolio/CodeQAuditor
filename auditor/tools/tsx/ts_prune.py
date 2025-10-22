# auditor/tools/ts_prune.py
from __future__ import annotations

import os
import re
import shlex
import subprocess
import time
from pathlib import Path
from typing import List, Optional

from ..base import AuditTool, Finding, ToolRunResult
from .nodejs import NodeToolMixin

# legacy line:  src/components/Button.tsx:Button - unused
_P_UNUSED = re.compile(
    r"^(?P<file>[^:]+):(?:(?P<line>\d+)\s*-\s*)?(?P<symbol>.+?)\s*-\s*unused\b.*$",
    re.IGNORECASE,
)

# annotated line: "file:line - Symbol" (maybe "(used in module)")
_P_GENERIC = re.compile(
    r"^(?P<file>[^:]+):(?P<line>\d+)\s*-\s*(?P<symbol>.+?)(?:\s+\((?P<note>used in module)\))?\s*$",
    re.IGNORECASE,
)

_IGNORED_DIRS = {
    "node_modules",
    ".git",
    ".next",
    "dist",
    "build",
    "out",
    ".output",
    ".turbo",
    ".cache",
    ".pnpm",
    ".yarn",
    ".venv",
    "venv",
    "__pycache__",
}


class TsPruneTool(AuditTool, NodeToolMixin):
    """
    ts-prune wrapper that supports multi-project folders.

    - Recursively discovers *all* subdirectories (any depth) containing a tsconfig.*
    - Runs ts-prune in each project and concatenates stdout into a single stream.
    - Each line is prefixed with the absolute project path so we can resolve files
      relative to the top-level path during parsing.
    - If no tsconfig is found under the given path, we emit nothing and succeed.
    """

    @property
    def name(self) -> str:
        return "ts-prune"

    def __init__(
        self,
        project: Optional[str] = None,               # force a specific tsconfig name, e.g. "tsconfig.json"
        include_globs: Optional[List[str]] = None,   # e.g. ["src/**/*.{ts,tsx}"]
        extra_args: Optional[List[str]] = None,
        package_version: Optional[str] = None,       # e.g., "^0.12"
        **kw,
    ):
        super().__init__(**kw)
        self.project = project
        self.include_globs = include_globs or []
        self.extra_args = extra_args or []
        self.package_version = package_version

    # ---------- command builder (single ToolRunResult, multi-project execution) ----------

    def build_cmd(self, path: str) -> List[str]:
        """
        Build a bash command that:
          - finds all tsconfig.* files under `path`
          - groups by directory (project roots)
          - runs ts-prune once per project
          - prefixes each output line with the absolute project path "<proj>/" so parse() can resolve paths
        """
        root = Path(path).resolve()

        # Discover projects now (in Python) to avoid spawning ts-prune in the wrong folder.
        projects = self._discover_ts_projects(root)
        if not projects:
            # No TS projects -> run a no-op that exits 0 and prints nothing
            return ["/bin/bash", "-lc", "true"]

        # npx prefix (where packages should install/cached)
        npx_prefix = str(self._node_prefix())

        # Compose CLI fragments
        include_bits = " ".join(shlex.quote(bit) for g in self.include_globs for bit in ("-i", g))
        extra_bits = " ".join(shlex.quote(a) for a in self.extra_args)

        # Encode projects as an array of "path:::tsconfig" entries to keep it robust against spaces
        entries = " ".join(
            shlex.quote(f"{p}:::{cfg}") for (p, cfg) in projects
        )

        script = f"""
set -euo pipefail
entries=({entries})
for entry in "${{entries[@]}}"; do
  proj="${{entry%%:::*}}"
  cfg="${{entry##*:::}}"
  # Run ts-prune inside the project dir, then prefix absolute project path to each output line.
  (
    cd "$proj"
    P="$PWD"
    npx --yes --prefix {shlex.quote(npx_prefix)} ts-prune -p "$cfg" {include_bits} {extra_bits} || true
  ) | sed "s#^#${{proj}}/#"
done
"""
        # Run the whole script from the provided root path
        return ["/bin/bash", "-lc", script]

    # ---------- discovery ----------

    def _discover_ts_projects(self, root: Path) -> List[tuple[str, str]]:
        """
        Return a list of (project_abs_path, tsconfig_filename) tuples.
        Preference per directory:
          1) tsconfig.json
          2) tsconfig.build.json
          3) tsconfig.base.json
        If self.project is set, only directories containing that file are selected.
        """
        root = root.resolve()
        projects: List[tuple[str, str]] = []

        def choose_tsconfig(d: Path) -> Optional[str]:
            if self.project:
                return self.project if (d / self.project).exists() else None
            if (d / "tsconfig.json").exists():
                return "tsconfig.json"
            if (d / "tsconfig.build.json").exists():
                return "tsconfig.build.json"
            if (d / "tsconfig.base.json").exists():
                return "tsconfig.base.json"
            return None

        for dirpath, dirnames, _ in os.walk(root, topdown=True, followlinks=False):
            # prune noisy dirs
            dirnames[:] = [d for d in dirnames if d not in _IGNORED_DIRS and not d.startswith(".git")]
            dpath = Path(dirpath)
            cfg = choose_tsconfig(dpath)
            if cfg:
                projects.append((str(dpath), cfg))

        # dedupe
        seen = set()
        uniq: List[tuple[str, str]] = []
        for p, cfg in projects:
            key = (p, cfg)
            if key not in seen:
                seen.add(key)
                uniq.append((p, cfg))
        return uniq

    # ---------- parser ----------

    def parse(self, result: ToolRunResult) -> List[Finding]:
        """
        Parse concatenated ts-prune output. Because build_cmd prefixes each line with "<abs_project>/" we
        can resolve against the tool run's root (`result.cwd`) safely and then relativize.
        """
        root = Path(result.cwd).resolve()
        findings: List[Finding] = []

        for raw in (result.stdout or "").splitlines():
            line = raw.strip()
            if not line:
                continue

            # A) Explicit "- unused"
            m = _P_UNUSED.match(line)
            if m:
                file_path = m.group("file")
                symbol = (m.group("symbol") or "").strip()
                line_no = m.group("line")
                if self._is_framework_reserved_export(file_path, symbol):
                    continue
                findings.append(self._make_finding(root, file_path, symbol, line_no, line))
                continue

            # B) Annotated with optional "(used in module)"
            g = _P_GENERIC.match(line)
            if not g:
                continue
            if (g.group("note") or "").lower().strip() == "used in module":
                continue

            file_path = g.group("file")
            symbol = (g.group("symbol") or "").strip()
            line_no = g.group("line")
            if self._is_framework_reserved_export(file_path, symbol):
                continue
            findings.append(self._make_finding(root, file_path, symbol, line_no, line))

        return findings

    # ---------- helpers ----------

    @staticmethod
    def _parts_after(parts: List[str], token: str) -> List[str]:
        token = token.lower()
        lower = [p.lower() for p in parts]
        if token in lower:
            idx = lower.index(token)
            return lower[idx + 1 :]
        return []

    @staticmethod
    def _is_framework_reserved_export(file_path: str, symbol: str) -> bool:
        """
        Filter common Next.js "magic" exports that ts-prune may treat as unused.
        """
        p = Path(file_path)
        name = p.stem.lower()  # e.g., "layout", "page", "middleware", "route"
        sym = symbol.strip()

        parts_lower = [s.lower() for s in p.parts]
        in_app_tree = ("app" in parts_lower) or ("app" in TsPruneTool._parts_after(parts_lower, "src"))

        # Middleware variants: middleware.ts, middleware.disabled.ts, etc.
        if name.startswith("middleware"):
            return sym in {"middleware", "config"}

        # Route handlers in app router: app/**/route.ts
        if in_app_tree and name == "route":
            http_methods = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}
            config_keys = {"dynamic", "revalidate", "runtime", "preferredRegion", "maxDuration"}
            return sym in http_methods or sym in config_keys

        # Page/Layout/template/etc files in app router
        next_app_files = {"layout", "page", "template", "not-found", "error", "loading"}
        next_reserved_symbols = {
            "default",
            "metadata",
            "generateMetadata",
            "viewport",
            "generateViewport",
            "generateStaticParams",
            "dynamic",
            "revalidate",
            "runtime",
            "preferredRegion",
            "maxDuration",
        }
        if in_app_tree and name in next_app_files:
            return sym in next_reserved_symbols

        return False

    def _make_finding(
        self,
        root: Path,
        file_path: str,
        symbol: str,
        line_no: Optional[str],
        raw: str,
    ) -> Finding:
        try:
            # file_path is absolute (we prefixed it), so relativize against the original cwd.
            rel = str(Path(file_path).resolve().relative_to(root))
        except Exception:
            rel = file_path
        line_int = int(line_no) if line_no and line_no.isdigit() else None
        return Finding(
            name="tsprune.unused-export",
            tool=self.name,
            rule_id="unused-export",
            message=f"Unused export: {symbol}",
            file=rel,
            line=line_int,
            col=None,
            extra={"symbol": symbol, "raw": raw},
            kind="analysis",
            category="deadcode",
            tags=["ts-prune", "unused", "export"],
            metrics={"count": 1.0},
        )
