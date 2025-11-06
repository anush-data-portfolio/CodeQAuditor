"""Bandit security analysis tool implementation.

This module implements the Bandit tool wrapper for finding security issues
in Python code.

Classes
-------
BanditTool : Bandit tool implementation

Examples
--------
>>> tool = BanditTool()
>>> if tool.is_installed():
...     result = tool.audit("myfile.py")

See Also
--------
auditor.infra.tools.base : Base tool class
auditor.core.models.parsers.bandit : Result parser
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, List, Optional

from auditor.core.models import ToolRunResult

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
        severity_level: str = "low",
        confidence_level: str = "low",
        processes: Optional[int] = None,
        quiet: bool = True,
        extra_args: Optional[List[str]] = None,
        **kw: Any,
    ) -> None:
        super().__init__(**kw)
        self.severity_level = severity_level
        self.confidence_level = confidence_level
        self.processes = processes
        self.quiet = quiet
        self.extra_args = extra_args or []

    def build_cmd(self, path: str) -> List[str]:
        cmd: List[str] = ["bandit", "-r", path, "--format", "json"]
        if self.severity_level:
            cmd += ["--severity-level", self.severity_level]
        if self.confidence_level:
            cmd += ["--confidence-level", self.confidence_level]
        if self.processes is not None:
            cmd += ["-n", str(self.processes)]
        if self.quiet:
            cmd.append("-q")
        cmd += self.extra_args
        return cmd

    def parse(self, result: ToolRunResult) -> None:  # noqa: D401 - intentional no-op
        """Placeholder hook for future schema integration."""
        return None


__all__ = ["BanditTool"]
