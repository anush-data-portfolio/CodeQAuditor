"""Mypy static type checker tool implementation.

This module implements the Mypy tool wrapper for static type checking
of Python code.

Classes
-------
MypyTool : Mypy tool implementation

Examples
--------
>>> tool = MypyTool()
>>> result = tool.audit("myfile.py")

See Also
--------
auditor.infra.tools.base : Base tool class
auditor.core.models.parsers.mypy : Result parser
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any, List, Optional, Union

from auditor.core.models import ToolRunResult

from ..base import CommandAuditTool


class MypyTool(CommandAuditTool):
    """
    Run mypy with configurable flags and return the raw ToolRunResult.
    """

    @property
    def name(self) -> str:
        return "mypy"

    def __init__(
        self,
        python_version: Optional[str] = "3.12",
        ignore_missing_imports: bool = True,
        follow_imports: str = "silent",
        install_types: bool = False,
        strict: bool = False,
        collapse_notes: bool = True,
        drop_external_notes: bool = True,
        **kw: Any,
    ) -> None:
        super().__init__(**kw)
        self.python_version = python_version
        self.ignore_missing_imports = ignore_missing_imports
        self.follow_imports = follow_imports
        self.install_types = install_types
        self.strict = strict
        self.collapse_notes = collapse_notes
        self.drop_external_notes = drop_external_notes

    def build_cmd(self, path: str) -> List[str]:
        with tempfile.TemporaryDirectory(prefix="auditor-mypy-") as tmp:
            reports_dir = Path(tmp) / "reports"
            cache_dir = Path(tmp) / "cache"
            reports_dir.mkdir(parents=True, exist_ok=True)
            cache_dir.mkdir(parents=True, exist_ok=True)

            cmd: List[str] = [
                "mypy",
                path,
                "--output",
                "json",
                "--no-site-packages",
                "--explicit-package-bases",
                "--show-error-end",
                "--show-column-numbers",
                "--sqlite-cache",
                "--cache-dir",
                str(cache_dir),
            ]
            if self.python_version:
                cmd += ["--python-version", self.python_version]
            if self.ignore_missing_imports:
                cmd += ["--ignore-missing-imports"]
            if self.follow_imports:
                cmd += ["--follow-imports", self.follow_imports]
            if self.strict:
                cmd += ["--strict"]
            return cmd, cache_dir


    def audit(self, path: Union[str, Path]) -> ToolRunResult:
        path_str = Path(path).absolute()
        cwd_str = str(Path(path_str).parent)
        cmd, cache_dir = self.build_cmd(str(path_str))

        self.env["MYPY_CACHE_DIR"] = str(cache_dir)
        raw_run = self._run(cmd, cwd=cwd_str)
        return raw_run



    def parse(self, result: ToolRunResult) -> None:  # noqa: D401 - intentional no-op
        """Placeholder hook for future schema integration."""
        return None


__all__ = ["MypyTool"]
