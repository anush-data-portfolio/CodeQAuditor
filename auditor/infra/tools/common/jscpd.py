"""JSCPD copy-paste detector tool implementation.

This module implements the JSCPD tool wrapper for detecting code duplication
across multiple languages.

Classes
-------
JSCPDTool : JSCPD tool implementation

Examples
--------
>>> tool = JSCPDTool()
>>> result = tool.audit("/path/to/project")

See Also
--------
auditor.infra.tools.base : Base tool class
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Iterable, List, Optional

from auditor.core.models import ToolRunResult
from audit.ignore_paths import get_shell_ignore_patterns

from ..base import AuditTool


class JscpdTool(AuditTool):
    """
    Minimal JSCPD wrapper that runs the tool and exposes the raw JSON payload.
    """

    @property
    def name(self) -> str:
        return "jscpd"

    def __init__(
        self,
        patterns: Optional[Iterable[str]] = None,
        formats: Optional[Iterable[str]] = None,
        ignore_globs: Optional[Iterable[str]] = None,
        min_tokens: Optional[int] = None,
        min_lines: Optional[int] = None,
        gitignore: bool = True,
        extra_args: Optional[List[str]] = None,
        **kw,
    ) -> None:
        super().__init__(**kw)
        self.patterns = list(patterns or [])
        self.formats = list(formats or [])
        self.ignore_globs = list(ignore_globs or [])
        self.min_tokens = min_tokens
        self.min_lines = min_lines
        self.gitignore = gitignore
        self.extra_args = extra_args or []
        extra_ignores = get_shell_ignore_patterns()
        if extra_ignores:
            existing = list(self.ignore_globs)
            for pattern in extra_ignores:
                if pattern not in existing:
                    existing.append(pattern)
            self.ignore_globs = existing

    def build_cmd(self, path: str) -> List[str]:
        return ["jscpd", "--help"]

    def audit(self, path):
        repo = Path(path).resolve()
        with tempfile.TemporaryDirectory(prefix="jscpd-") as tmpdir:
            out_dir = Path(tmpdir)
            cmd: List[str] = [
                "jscpd",
                "--reporters",
                "json",
                "--silent",
                "--output",
                str(out_dir),
            ]

            if self.formats:
                cmd += ["--format", ",".join(self.formats)]
            for pat in self.patterns:
                cmd += ["--pattern", pat]
            if self.gitignore:
                cmd.append("--gitignore")
            for pat in self.ignore_globs:
                cmd += ["--ignore", pat]
            if self.min_tokens is not None:
                cmd += ["--min-tokens", str(self.min_tokens)]
            if self.min_lines is not None:
                cmd += ["--min-lines", str(self.min_lines)]
            if self.extra_args:
                cmd += self.extra_args
            cmd.append(str(repo))

            run = self._run(cmd, cwd=str(repo))

            parsed = run.parsed_json
            if parsed is None:
                report_path = out_dir / "jscpd-report.json"
                if report_path.exists():
                    try:
                        parsed = json.loads(
                            report_path.read_text(encoding="utf-8", errors="ignore")
                        )
                    except Exception:
                        parsed = None

            if parsed is not None and run.parsed_json is None:
                run = ToolRunResult(
                    tool=run.tool,
                    cmd=run.cmd,
                    cwd=run.cwd,
                    returncode=run.returncode,
                    duration_s=run.duration_s,
                    stdout=run.stdout,
                    stderr=run.stderr,
                    parsed_json=parsed,
                )

        self.parse(run)
        return run

    def parse(self, result: ToolRunResult) -> None:
        """Placeholder hook for future schema integration."""
        return None


__all__ = ["JscpdTool"]
