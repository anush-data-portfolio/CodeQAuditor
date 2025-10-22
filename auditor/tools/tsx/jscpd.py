# auditor/tools/jscpd.py
from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..base import AuditTool, Finding, ToolRunResult
from .nodejs import NodeToolMixin


def _rel(root: Path, p: str | None) -> Optional[str]:
    if not p:
        return None
    try:
        return str(Path(p).resolve().relative_to(root.resolve()))
    except Exception:
        return str(p)


def _fp_key(a_file: str, a_start: int, a_end: int, b_file: str, b_start: int, b_end: int, fragment: str | None) -> str:
    # Canonicalize pair ordering so A↔B isn’t duplicated
    pair = sorted(
        [(a_file, a_start, a_end), (b_file, b_start, b_end)],
        key=lambda t: (t[0], t[1], t[2]),
    )
    base = f"{pair[0][0]}:{pair[0][1]}-{pair[0][2]}|{pair[1][0]}:{pair[1][1]}-{pair[1][2]}"
    if fragment:
        base += "|" + hashlib.sha1(fragment.encode("utf-8", "ignore")).hexdigest()
    return hashlib.sha1(base.encode("utf-8", "ignore")).hexdigest()


class JscpdTool(AuditTool, NodeToolMixin):
    """
    JSCPD exact duplicate detector (multi-language).
    - Emits issue rows per clone pair (canonicalized).
    - Emits per-file analysis rows (when available in report).
    - Emits a repo summary row.
    """

    @property
    def name(self) -> str:
        return "jscpd"

    def __init__(
        self,
        # Limit scope and noise by default to app code:
        patterns: Optional[List[str]] = None,             # e.g., ["**/*.{ts,tsx,js,jsx}"]
        ignore_globs: Optional[List[str]] = None,         # jscpd --ignore patterns
        formats: Optional[List[str]] = None,              # e.g., ["javascript","typescript"]
        min_tokens: Optional[int] = 50,
        package_version: Optional[str] = None,            # e.g., "^4"
        extra_args: Optional[List[str]] = None,
        **kw: Any,
    ) -> None:
        super().__init__(**kw)
        self.patterns = patterns or ["**/*.{ts,tsx,js,jsx}"]
        self.ignore_globs = ignore_globs or [
            "**/.git/**", "**/.hg/**", "**/.svn/**",
            "**/node_modules/**", "**/dist/**", "**/build/**",
            "**/.next/**", "**/out/**",
            "**/.cache/**", "**/.turbo/**",
            "**/__pycache__/**", "**/.mypy_cache/**",
            "**/.tox/**",
        ]
        # jscpd understands high-level languages; it will handle JSX/TSX under these
        self.formats = formats or ["javascript", "typescript"]
        self.min_tokens = min_tokens
        self.package_version = package_version
        self.extra_args = extra_args or []

    # We override audit() to capture the JSON file jscpd writes.
    def build_cmd(self, path: str) -> List[str]:
        # Not used (audit overrides), but keep a reasonable default
        return ["jscpd", "--reporters", "json", "."]

    def audit(self, path: str) -> Tuple[List[Finding], ToolRunResult]:
        repo = Path(path).resolve()
        with tempfile.TemporaryDirectory(prefix="jscpd-") as tmpdir:
            out_dir = Path(tmpdir)
            # Build a local (npx) command via NodeToolMixin
            base = self._node_cmd(
                cwd=repo,
                exe="jscpd",
                npm_package="jscpd",
                version=self.package_version,
                extra=[
                    "--reporters", "json",
                    "--silent",
                    "--gitignore",  # respect .gitignore
                    "--output", str(out_dir),
                ],
            )
            # Formats, patterns, ignores
            if self.formats:
                base += ["--format", ",".join(self.formats)]
            if self.min_tokens is not None:
                base += ["--min-tokens", str(self.min_tokens)]
            for pat in self.ignore_globs:
                base += ["--ignore", pat]
            for pat in self.patterns:
                base += ["--pattern", pat]
            base += self.extra_args

            run = self._run(base, cwd=str(repo))

            # jscpd writes JSON file, typically jscpd-report.json
            report_path = out_dir / "jscpd-report.json"
            parsed: Optional[Dict[str, Any]] = None
            if report_path.exists():
                try:
                    parsed = json.loads(report_path.read_text(encoding="utf-8", errors="ignore"))
                except Exception:
                    parsed = None

            # Synthesize a ToolRunResult with parsed_json for the parser
            synthesized = ToolRunResult(
                tool=self.name,
                cmd=base,
                cwd=str(repo),
                returncode=run.returncode,
                duration_s=run.duration_s,
                stdout=run.stdout,
                stderr=run.stderr,
                parsed_json=parsed,
            )
            findings = self.parse(synthesized)
            return findings, synthesized

    def parse(self, result: ToolRunResult) -> List[Finding]:
        root = Path(result.cwd).resolve()
        data = result.parsed_json or {}
        findings: List[Finding] = []

        # Defensive: accept list/dict; prefer dict with "duplicates"
        if not isinstance(data, dict):
            try:
                data = json.loads(result.stdout or "{}")
            except Exception:
                data = {}

        # --- Per-clone issues ----------------------------------------------------
        seen_keys: set[str] = set()
        dups = data.get("duplicates") or []
        if isinstance(dups, list):
            for d in dups:
                if not isinstance(d, dict):
                    continue
                first = d.get("firstFile", {}) or {}
                second = d.get("secondFile", {}) or {}
                fmt = d.get("format") or d.get("lang") or ""

                a_file = _rel(root, first.get("name"))
                b_file = _rel(root, second.get("name"))

                a_sline = (((first.get("startLoc") or {}).get("line")) or first.get("start") or None)
                a_scol = (((first.get("startLoc") or {}).get("column")) or None)
                a_eline = (((first.get("endLoc") or {}).get("line")) or first.get("end") or None)
                a_ecol = (((first.get("endLoc") or {}).get("column")) or None)

                b_sline = (((second.get("startLoc") or {}).get("line")) or second.get("start") or None)
                b_scol = (((second.get("startLoc") or {}).get("column")) or None)
                b_eline = (((second.get("endLoc") or {}).get("line")) or second.get("end") or None)
                b_ecol = (((second.get("endLoc") or {}).get("column")) or None)

                # Normalize to ints when possible
                def _toi(x): 
                    try: 
                        return int(x) 
                    except Exception: 
                        return None
                a_sline, a_scol, a_eline, a_ecol = map(_toi, (a_sline, a_scol, a_eline, a_ecol))
                b_sline, b_scol, b_eline, b_ecol = map(_toi, (b_sline, b_scol, b_eline, b_ecol))

                fragment = (d.get("fragment") or d.get("raw", {}).get("fragment")) if isinstance(d.get("raw"), dict) else d.get("fragment")
                key = _fp_key(a_file or "", a_sline or 0, a_eline or 0, b_file or "", b_sline or 0, b_eline or 0, fragment or None)
                if key in seen_keys:
                    continue
                seen_keys.add(key)

                lines = d.get("lines") or d.get("raw", {}).get("lines") or d.get("raw", {}).get("firstFile", {}).get("lines")
                tokens = d.get("tokens") or d.get("raw", {}).get("tokens")

                # Construct message
                msg = (
                    f"Duplicate block ({lines or 'n/a'} lines"
                    f"{', ' + str(tokens) + ' tokens' if tokens is not None else ''}) "
                    f"between {a_file}:{a_sline}-{a_eline} and {b_file}:{b_sline}-{b_eline}"
                )

                findings.append(
                    Finding(
                        name="jscpd.duplicate",
                        tool=self.name,
                        rule_id="duplicate",
                        message=msg,
                        file=a_file,
                        line=a_sline,
                        col=a_scol,
                        end_line=a_eline,
                        end_col=a_ecol,
                        fingerprint=key,
                        extra={
                            "counterpart": {
                                "file": b_file,
                                "start_line": b_sline,
                                "end_line": b_eline,
                                "start_col": b_scol,
                                "end_col": b_ecol,
                            },
                            "format": fmt,
                            "lines": lines,
                            "tokens": tokens,
                        },
                        kind="issue",
                        category="duplication",
                        tags=["jscpd", "duplicate", f"format:{fmt}"] if fmt else ["jscpd", "duplicate"],
                        metrics={
                            "lines": float(lines) if isinstance(lines, (int, float)) else 0.0,
                            "tokens": float(tokens) if isinstance(tokens, (int, float)) else 0.0,
                        },
                    )
                )

        # --- Per-file analysis (if available) -----------------------------------
        # Some jscpd versions include per-format → sources metrics
        stats = (data.get("statistics") or {}).get("formats") or {}
        if isinstance(stats, dict):
            for _fmt, payload in stats.items():
                sources = (payload or {}).get("sources") or {}
                if not isinstance(sources, dict):
                    continue
                for fpath, meta in sources.items():
                    # meta may have clones, duplicatedLines, percentage, tokens, lines
                    rel = _rel(root, fpath)
                    clones = float(meta.get("clones") or 0)
                    dupl_lines = float(meta.get("duplicatedLines") or 0)
                    pct = float(meta.get("percentage") or 0)
                    findings.append(
                        Finding(
                            name="jscpd.file",
                            tool="jscpd-metrics",
                            rule_id="file",
                            message=f"duplication: {int(clones)} clones, {int(dupl_lines)} duplicated lines ({pct}%)",
                            file=rel,
                            line=None,
                            col=None,
                            extra=meta,
                            kind="analysis",
                            category="duplication",
                            tags=["jscpd", "file-metrics"],
                            metrics={"clones": clones, "duplicated_lines": dupl_lines, "percentage": pct},
                        )
                    )

        return findings
