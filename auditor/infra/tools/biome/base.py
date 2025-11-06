"""Biome linter/formatter tool implementation.

This module implements the Biome tool wrapper for linting and formatting
JavaScript, TypeScript, JSX, and TSX code.

Classes
-------
BiomeTool : Biome tool implementation

Examples
--------
>>> tool = BiomeTool()
>>> result = tool.audit("app.tsx")

See Also
--------
auditor.infra.tools.base : Base tool class
auditor.core.models.parsers.biome : Result parser
"""
from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from auditor.core.models import ToolRunResult

from ..base import CommandAuditTool, NodeToolMixin

DEFAULT_EXTS = [".ts", ".tsx", ".js", ".jsx"]


class BiomeTool(CommandAuditTool, NodeToolMixin):
    """Lightweight Biome runner that returns the raw ToolRunResult."""

    @property
    def name(self) -> str:
        return "biome"

    def __init__(
        self,
        exts: Optional[List[str]] = None,
        config_path: Optional[str] = None,
        extra_args: Optional[List[str]] = None,
        package_version: Optional[str] = None,
        **kw,
    ) -> None:
        super().__init__(**kw)
        self.exts = exts or list(DEFAULT_EXTS)
        self.config_path = Path(config_path).resolve() if config_path else None
        self.extra_args = extra_args or []
        self.package_version = package_version

    def build_cmd(self, path: str, cwd: Optional[Path] = None) -> List[str]:
        self._prepare_node_env()

        # Base command with check subcommand
        cmd = self._node_cmd(
            exe="biome",
            cwd=cwd,
            npm_package="@biomejs/biome",
            version=self.package_version,
            subcommand=["check"],
            extra=[],
        )

        # Add the path to check
        cmd.append(path)

        # Output format
        cmd += [
            "--reporter", "json-pretty",
            "--colors", "off",
            "--log-level", "none",
            "--formatter-enabled=false",
            "--linter-enabled=false",
            "--assist-enabled=false",
            "--no-errors-on-unmatched",
        ]

        # Config file if specified
        if self.config_path:
            cmd += ["--config-path", str(self.config_path)]

        # Additional arguments
        cmd += self.extra_args

        return cmd

    def audit(self, path: str | Path) -> ToolRunResult:
        # If it's a non-JS/TS file, skip Biome
        path_str = str(path)
        if not any(path_str.endswith(ext) for ext in self.exts):
            return ToolRunResult(
                tool=self.name,
                cmd=[str(path)],
                cwd=str(path),
                returncode=0,
                duration_s=0.0,
                stdout="",
                stderr="",
                parsed_json={"diagnostics": []},
            )
        return super().audit(path)

    def parse(self, result: ToolRunResult) -> None:
        return None


__all__ = ["BiomeTool"]
