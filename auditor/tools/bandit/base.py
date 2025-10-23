from __future__ import annotations

from pathlib import Path
from typing import Any, List, Optional

from auditor.models import ToolRunResult

from ..base import CommandAuditTool


class BanditTool(CommandAuditTool):
    """
    Thin wrapper around `bandit -r` that returns the raw ToolRunResult.
    """

    @property
    def name(self) -> str:
        return "bandit"

    def __init__(
        self,
        *,
        severity_level: str = "medium",
        confidence_level: str = "medium",
        exclude_globs: Optional[List[str]] = None,
        processes: Optional[int] = None,
        quiet: bool = True,
        extra_args: Optional[List[str]] = None,
        **kw: Any,
    ) -> None:
        super().__init__(**kw)
        self.severity_level = severity_level
        self.confidence_level = confidence_level
        self.exclude_globs = exclude_globs or [
            ".git",
            ".hg",
            ".mypy_cache",
            ".ruff_cache",
            ".venv",
            "venv",
            "build",
            "dist",
            "site-packages",
            "__pycache__",
        ]
        self.processes = processes
        self.quiet = quiet
        self.extra_args = extra_args or []

    def build_cmd(self, path: str) -> List[str]:
        target = str(Path(path).resolve())
        cmd: List[str] = ["bandit", "-r", target, "--format", "json"]

        if self.severity_level:
            cmd += ["--severity-level", self.severity_level]
        if self.confidence_level:
            cmd += ["--confidence-level", self.confidence_level]
        if self.processes is not None:
            cmd += ["-n", str(self.processes)]
        if self.exclude_globs:
            cmd += ["--exclude", ",".join(self.exclude_globs)]
        if self.quiet:
            cmd.append("-q")

        cmd += self.extra_args
        return cmd

    def audit(self, path):
        return super().audit(path)

    def parse(self, result: ToolRunResult) -> None:  # noqa: D401 - intentional no-op
        """Placeholder hook for future schema integration."""
        return None


__all__ = ["BanditTool"]
