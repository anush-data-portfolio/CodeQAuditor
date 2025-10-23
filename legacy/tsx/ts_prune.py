from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from auditor.models import ToolRunResult

from ..base import CommandAuditTool
from .nodejs import NodeToolMixin


class TsPruneTool(CommandAuditTool, NodeToolMixin):
    """Minimal ts-prune wrapper that returns the raw ToolRunResult."""

    @property
    def name(self) -> str:
        return "ts-prune"

    def __init__(
        self,
        args: Optional[List[str]] = None,
        package_version: Optional[str] = None,
        **kw,
    ) -> None:
        super().__init__(**kw)
        self.args = args or []
        self.package_version = package_version

    def build_cmd(self, path: str) -> List[str]:
        cwd = Path(path).resolve()
        cmd = self._node_cmd(
            cwd=cwd,
            exe="ts-prune",
            npm_package="ts-prune",
            version=self.package_version,
            extra=[*self.args],
        )
        return cmd

    def parse(self, result: ToolRunResult) -> None:
        """Placeholder hook for future schema integration."""
        return None


__all__ = ["TsPruneTool"]
