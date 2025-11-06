"""Snyk Code SAST tool implementation.

This module implements the Snyk Code tool wrapper for detecting security
vulnerabilities and code quality issues in source code.

Classes
-------
SnykTool : Snyk Code tool implementation

Examples
--------
>>> tool = SnykTool()
>>> if tool.is_installed():
...     result = tool.audit("/path/to/code")

See Also
--------
auditor.infra.tools.base : Base tool class
auditor.core.models.parsers.snyk : Result parser
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, List, Optional

from auditor.core.models import ToolRunResult
from ..base import CommandAuditTool


class SnykTool(CommandAuditTool):
    """
    Wrapper for Snyk Code CLI execution.
    
    Snyk Code performs static application security testing (SAST) to find:
    - Security vulnerabilities (XSS, SQL injection, etc.)
    - Code quality issues
    - Hardcoded secrets
    - Insecure configurations
    
    Outputs results in SARIF format.
    
    Inherits from CommandAuditTool for command execution.
    """
    
    @property
    def name(self) -> str:
        """Tool identifier used in database and CLI."""
        return "snyk"
    
    def __init__(
        self,
        *,
        severity_threshold: Optional[str] = None,
        json_output: bool = True,
        sarif: bool = True,
        all_projects: bool = False,
        org: Optional[str] = None,
        extra_args: Optional[List[str]] = None,
        **kw: Any,
    ) -> None:
        """
        Initialize Snyk wrapper.
        
        Parameters
        ----------
        severity_threshold : str, optional
            Minimum severity to report: low, medium, high, critical
        json_output : bool
            Output JSON format (default: True)
        sarif : bool
            Output SARIF format (default: True, required for parser)
        all_projects : bool
            Detect and scan all projects in directory (default: False)
        org : str, optional
            Snyk organization ID to use
        extra_args : List[str], optional
            Additional CLI arguments
        **kw : Any
            Passed to CommandAuditTool (timeout_s, mem_mb, etc.)
        """
        super().__init__(**kw)
        self.severity_threshold = severity_threshold
        self.json_output = json_output
        self.sarif = sarif
        self.all_projects = all_projects
        self.org = org
        self.extra_args = extra_args or []
    
    def build_cmd(self, path: str) -> List[str]:
        """
        Build command-line arguments for Snyk Code.
        
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
        >>> tool = SnykTool()
        >>> tool.build_cmd("/path/to/code")
        ['snyk', 'code', 'test', '.', '--json', '--sarif']
        """
        cmd: List[str] = ["snyk", "code", "test"]
        
        # Target path (Snyk uses "." for current directory)
        # When running from cwd, use "."
        cmd.append(path)
        
        # Output formats
        if self.json_output:
            cmd.append("--json")
        
        if self.sarif:
            cmd.append("--sarif")
        
        # Severity threshold
        if self.severity_threshold:
            cmd += ["--severity-threshold", self.severity_threshold]
        
        # Organization
        if self.org:
            cmd += ["--org", self.org]
        
        # All projects
        if self.all_projects:
            cmd.append("--all-projects")
        
        # Additional arguments
        cmd += self.extra_args
        
        return cmd
    
    def audit(self, path: str | Path) -> ToolRunResult:
        """
        Run Snyk Code analysis on the specified path.
        
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
        Snyk returns non-zero exit codes when issues are found:
        - 1: Vulnerabilities found
        - 2: Command failed
        We handle exit code 1 as successful scan with findings.
        """
        path_str = str(Path(path).resolve())
        cwd_str = str(Path(path_str).parent) if Path(path_str).is_file() else path_str
        
        cmd = self.build_cmd(path_str)
        result = self._run(cmd, cwd=cwd_str)
        
        # Snyk returns exit code 1 when vulnerabilities are found
        # This is expected behavior, not an error
        if result.returncode == 1 and result.stdout:
            # Try to parse SARIF from stdout
            try:
                result.parsed_json = json.loads(result.stdout)
            except json.JSONDecodeError:
                # If stdout isn't JSON, leave parsed_json as is
                pass
        
        return result
    
    def parse(self, result: ToolRunResult) -> None:
        """
        Post-process Snyk results.
        
        Parameters
        ----------
        result : ToolRunResult
            Tool execution result
        """
        # Snyk writes SARIF to stdout
        # Ensure it's parsed if not already
        if not result.parsed_json and result.stdout:
            try:
                result.parsed_json = json.loads(result.stdout)
            except json.JSONDecodeError:
                result.parsed_json = {"runs": []}
        
        return None


__all__ = ["SnykTool"]
