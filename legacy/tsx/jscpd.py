from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import List, Optional

from auditor.models import ToolRunResult

from ..base import AuditTool
from .nodejs import NodeToolMixin


class JscpdTool(AuditTool, NodeToolMixin):
    """
    Minimal JSCPD wrapper for TS/JS projects that returns the raw ToolRunResult.
    """

    @property
    def name(self) -> str:
        return "jscpd"

    def __init__(
        self,
        patterns: Optional[List[str]] = None,
        ignore_globs: Optional[List[str]] = None,
        formats: Optional[List[str]] = None,
        min_tokens: Optional[int] = 50,
        package_version: Optional[str] = None,
        extra_args: Optional[List[str]] = None,
        **kw,
    ) -> None:
        super().__init__(**kw)
        self.patterns = patterns or ["**/*.{ts,tsx,js,jsx}"]
        self.ignore_globs = ignore_globs or [
            "**/.git/**",
            "**/.hg/**",
            "**/.svn/**",
            "**/node_modules/**",
            "**/dist/**",
            "**/build/**",
            "**/.next/**",
            "**/out/**",
            "**/.cache/**",
            "**/.turbo/**",
            "**/__pycache__/**",
            "**/.mypy_cache/**",
            "**/.tox/**",
        ]
        self.formats = formats or ["javascript", "typescript"]
        self.min_tokens = min_tokens
        self.package_version = package_version
        self.extra_args = extra_args or []

    def audit(self, path):
        repo = Path(path).resolve()
        with tempfile.TemporaryDirectory(prefix="jscpd-") as tmpdir:
            out_dir = Path(tmpdir)
            cmd = self._node_cmd(
                cwd=repo,
                exe="jscpd",
                npm_package="jscpd",
                version=self.package_version,
                extra=[
                    "--reporters",
                    "json",
                    "--silent",
                    "--gitignore",
                    "--output",
                    str(out_dir),
                ],
            )
            if self.formats:
                cmd += ["--format", ",".join(self.formats)]
            if self.min_tokens is not None:
                cmd += ["--min-tokens", str(self.min_tokens)]
            for pattern in self.ignore_globs:
                cmd += ["--ignore", pattern]
            for pattern in self.patterns:
                cmd += ["--pattern", pattern]
            cmd += self.extra_args

            run = self._run(cmd, cwd=str(repo))

            parsed = run.parsed_json
            if parsed is None:
                report_path = out_dir / "jscpd-report.json"
                if report_path.exists():
                    try:
                        parsed = json.loads(report_path.read_text(encoding="utf-8", errors="ignore"))
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
