from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from auditor.models import ToolRunResult

from ..base import CommandAuditTool
from .nodejs import NodeToolMixin


class TscTool(CommandAuditTool, NodeToolMixin):
    """Minimal `tsc --noEmit` wrapper that returns the raw ToolRunResult."""

    @property
    def name(self) -> str:
        return "tsc"

    def __init__(
        self,
        project: Optional[str] = None,
        extra_args: Optional[List[str]] = None,
        package_version: Optional[str] = None,
        **kw,
    ) -> None:
        super().__init__(**kw)
        self.project = project
        self.extra_args = extra_args or []
        self.package_version = package_version

    def build_cmd(self, path: str) -> List[str]:
        cwd = Path(path).resolve()
        cmd = self._node_cmd(
            cwd=cwd,
            exe="tsc",
            npm_package="typescript",
            version=self.package_version,
            extra=["--noEmit"],
        )
        if self.project:
            cmd += ["--project", self.project]
        cmd += self.extra_args
        return cmd

    def parse(self, result: ToolRunResult) -> None:
        """Placeholder hook for future schema integration."""
        return None


__all__ = ["TscTool"]
