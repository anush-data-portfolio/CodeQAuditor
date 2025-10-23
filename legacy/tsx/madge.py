from __future__ import annotations

from pathlib import Path
from typing import Iterable, List, Optional

from auditor.models import ToolRunResult

from ..base import CommandAuditTool
from .nodejs import NodeToolMixin


class MadgeTool(CommandAuditTool, NodeToolMixin):
    """Minimal Madge wrapper that returns the raw ToolRunResult."""

    @property
    def name(self) -> str:
        return "madge"

    def __init__(
        self,
        tsconfig: Optional[str] = None,
        extensions: Optional[Iterable[str]] = None,
        include_orphans: bool = True,
        include_circular: bool = True,
        external_exclude: Optional[List[str]] = None,
        extra_args: Optional[List[str]] = None,
        package_version: Optional[str] = None,
        **kw,
    ) -> None:
        super().__init__(**kw)
        self.tsconfig = tsconfig
        self.extensions = list(extensions or ["ts", "tsx", "js", "jsx"])
        self.include_orphans = include_orphans
        self.include_circular = include_circular
        self.external_exclude = external_exclude or []
        self.extra_args = extra_args or []
        self.package_version = package_version

    def build_cmd(self, path: str) -> List[str]:
        cwd = Path(path).resolve()
        cmd = self._node_cmd(
            cwd=cwd,
            exe="madge",
            npm_package="madge",
            version=self.package_version,
            extra=["--json", "--extensions", ",".join(self.extensions)],
        )
        if self.tsconfig:
            cmd += ["--ts-config", self.tsconfig]
        if self.include_orphans:
            cmd.append("--orphans")
        if self.include_circular:
            cmd.append("--circular")
        for pattern in self.external_exclude:
            cmd += ["--exclude", pattern]
        cmd += self.extra_args
        cmd.append(".")
        return cmd

    def parse(self, result: ToolRunResult) -> None:
        """Placeholder hook for future schema integration."""
        return None


__all__ = ["MadgeTool"]
