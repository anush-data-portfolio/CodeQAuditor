from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from auditor.models import ToolRunResult

from ..base import CommandAuditTool
from .nodejs import NodeToolMixin


class BiomeTool(CommandAuditTool, NodeToolMixin):
    """
    Lightweight wrapper around `biome check` that returns the raw ToolRunResult.
    """

    @property
    def name(self) -> str:
        return "biome"

    def __init__(
        self,
        paths: Optional[List[str]] = None,
        report_unformatted: bool = True,
        extra_args: Optional[List[str]] = None,
        package_version: Optional[str] = None,
        **kw,
    ):
        super().__init__(**kw)
        self.paths = paths or ["."]
        self.report_unformatted = report_unformatted
        self.extra_args = extra_args or []
        self.package_version = package_version

    def build_cmd(self, path: str) -> List[str]:
        cwd = Path(path).resolve()
        cmd = self._node_cmd(
            cwd=cwd,
            exe="biome",
            npm_package="@biomejs/biome",
            version=self.package_version,
            subcommand=["check"],
            extra=["--reporter", "json", *self.paths],
        )
        if not self.report_unformatted:
            cmd += ["--no-errors-on-unformatted"]
        cmd += self.extra_args
        return cmd

    def parse(self, result: ToolRunResult) -> None:
        """Placeholder hook for future schema integration."""
        return None


__all__ = ["BiomeTool"]
