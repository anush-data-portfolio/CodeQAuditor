"""Qlty code quality tool implementation.

This module implements the Qlty tool wrapper for running multiple linters
and formatters through a unified interface.

Classes
-------
QltyTool : Qlty tool implementation

Examples
--------
>>> tool = QltyTool()
>>> if tool.is_installed():
...     result = tool.audit("/path/to/code")

See Also
--------
auditor.infra.tools.base : Base tool class
auditor.core.models.parsers.qlty : Result parser
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, List, Optional

from auditor.core.models import ToolRunResult
from ..base import CommandAuditTool


class QltyTool(CommandAuditTool):
    """
    Wrapper for Qlty CLI execution.
    
    Qlty is a unified code quality platform that runs multiple linters
    and formatters. It can execute various tools like ESLint, Prettier,
    Ruff, and more through a single interface.
    
    Outputs results in SARIF format.
    
    Inherits from CommandAuditTool for command execution.
    """
    
    @property
    def name(self) -> str:
        """Tool identifier used in database and CLI."""
        return "qlty"
    
    def __init__(
        self,
        *,
        no_fix: bool = True,
        no_formatters: bool = True,
        sarif: bool = True,
        json_output: bool = False,
        extra_args: Optional[List[str]] = None,
        **kw: Any,
    ) -> None:
        """
        Initialize Qlty wrapper.
        
        Parameters
        ----------
        no_fix : bool
            Don't apply automatic fixes (default: True)
        no_formatters : bool
            Skip formatter tools (default: True)
        sarif : bool
            Output SARIF format (default: True, required for parser)
        json_output : bool
            Output JSON format instead of SARIF (default: False)
        extra_args : List[str], optional
            Additional CLI arguments
        **kw : Any
            Passed to CommandAuditTool (timeout_s, mem_mb, etc.)
        """
        super().__init__(**kw)
        self.no_fix = no_fix
        self.no_formatters = no_formatters
        self.sarif = sarif
        self.json_output = json_output
        self.extra_args = extra_args or []
    
    def build_cmd(self, path: str) -> List[str]:
        """
        Build command-line arguments for Qlty.
        
        Parameters
        ----------
        path : str
            Target file or directory to scan
        
        Returns
        -------
        List[str]
            Command and arguments
        
        Examples
        --------
        >>> tool = QltyTool()
        >>> tool.build_cmd("/path/to/code")
        ['qlty', 'check', '/path/to/code', '--no-fix', '--no-formatters', '--sarif']
        """
        cmd: List[str] = ["qlty", "check", path]
        
        # Don't apply fixes
        if self.no_fix:
            cmd.append("--no-fix")
        
        # Skip formatters
        if self.no_formatters:
            cmd.append("--no-formatters")
        
        # Output format
        if self.sarif:
            cmd.append("--sarif")
        elif self.json_output:
            cmd.append("--json")
        
        # Additional arguments
        cmd += self.extra_args
        
        return cmd
    
    def audit(self, path: str | Path) -> ToolRunResult:
        """
        Run Qlty analysis on the specified path.
        
        Parameters
        ----------
        path : str or Path
            Target file or directory to scan
        
        Returns
        -------
        ToolRunResult
            Standardized result with parsed SARIF findings
        
        Notes
        -----
        Qlty returns non-zero exit codes when issues are found.
        Exit code 1 typically means findings were detected, which
        we handle as a successful scan.
        """
        path_str = str(Path(path).resolve())
        cwd_str = str(Path(path_str).parent) if Path(path_str).is_file() else path_str
        
        cmd = self.build_cmd(path_str)
        result = self._run(cmd, cwd=cwd_str)
        
        # Qlty returns non-zero when issues are found
        # This is expected behavior, not an error
        if result.returncode != 0 and result.stdout:
            # Try to parse JSON/SARIF from stdout
            try:
                result.parsed_json = json.loads(result.stdout)
            except json.JSONDecodeError:
                # If stdout isn't valid JSON, leave as is
                pass
        
        return result
    
    def parse(self, result: ToolRunResult) -> None:
        """
        Post-process Qlty results.
        
        Parameters
        ----------
        result : ToolRunResult
            Tool execution result
        """
        # Qlty writes SARIF to stdout
        # Ensure it's parsed if not already
        if not result.parsed_json and result.stdout:
            try:
                result.parsed_json = json.loads(result.stdout)
            except json.JSONDecodeError:
                # Empty SARIF structure
                result.parsed_json = {"runs": []}
        
        return None


__all__ = ["QltyTool"]
