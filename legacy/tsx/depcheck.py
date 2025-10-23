from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from auditor.models import ToolRunResult

from ..base import CommandAuditTool
from .nodejs import NodeToolMixin


class DepcheckTool(CommandAuditTool, NodeToolMixin):
    """
    Minimal depcheck wrapper that returns the raw ToolRunResult.
    """

    @property
    def name(self) -> str:
        return "depcheck"

    def __init__(
        self,
        ignore_missing: bool = True,
        extra_args: Optional[List[str]] = None,
        package_version: Optional[str] = None,
        **kw,
    ):
        super().__init__(**kw)
        self.ignore_missing = ignore_missing
        self.extra_args = extra_args or []
        self.package_version = package_version

    def build_cmd(self, path: str) -> List[str]:
        cwd = Path(path).resolve()
        cmd = self._node_cmd(
            cwd=cwd,
            exe="depcheck",
            npm_package="depcheck",
            version=self.package_version,
            extra=["--json", "."],
        )
        cmd += self.extra_args
        return cmd

    def parse(self, result: ToolRunResult) -> None:
        """Placeholder hook for future schema integration."""
        return None


__all__ = ["DepcheckTool"]
