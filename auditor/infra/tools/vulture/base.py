"""Vulture dead code detection tool implementation.

This module implements the Vulture tool wrapper for finding unused code
in Python programs.

Classes
-------
VultureTool : Vulture tool implementation

Examples
--------
>>> tool = VultureTool()
>>> result = tool.audit("myfile.py")

See Also
--------
auditor.infra.tools.base : Base tool class
auditor.core.models.parsers.vulture : Result parser
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, List, Optional, Union

from auditor.core.models.schema import ToolRunResult

from ..base import CommandAuditTool


class VultureTool(CommandAuditTool):
    """
    Thin wrapper around `vulture` that returns the raw ToolRunResult.
    """

    @property
    def name(self) -> str:
        return "vulture"

    def __init__(
        self,
        *,
        min_confidence: int = 70,
        ignore_decorators: Optional[List[str]] = None,
        ignore_names: Optional[List[str]] = None,
        extra_args: Optional[List[str]] = None,
        **kw: Any,
    ) -> None:
        super().__init__(**kw)
        self.min_confidence = int(min_confidence)
        self.ignore_decorators = ignore_decorators or []
        self.ignore_names = ignore_names or []
        self.extra_args = extra_args or []

    def build_cmd(self, path: str) -> List[str]:
        cmd: List[str] = ["vulture"]
        if self.ignore_decorators:
            cmd += ["--ignore-decorators", ",".join(self.ignore_decorators)]
        if self.ignore_names:
            cmd += ["--ignore-names", ",".join(self.ignore_names)]
        cmd += ["--min-confidence", str(self.min_confidence)]
        cmd += self.extra_args
        cmd.append(path)
        return cmd


    def parse(self, result: ToolRunResult) -> None:  # noqa: D401
        """Placeholder hook for future schema integration."""
        return None


__all__ = ["VultureTool"]
