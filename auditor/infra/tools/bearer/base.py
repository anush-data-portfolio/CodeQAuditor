"""Bearer SAST tool implementation.

This module implements the Bearer tool wrapper for detecting security
vulnerabilities and privacy issues related to sensitive data flows.

Classes
-------
BearerTool : Bearer tool implementation

Examples
--------
>>> tool = BearerTool()
>>> if tool.is_installed():
...     result = tool.audit("/path/to/code")

See Also
--------
auditor.infra.tools.base : Base tool class
auditor.core.models.parsers.bearer : Result parser
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, List, Optional

from auditor.core.models import ToolRunResult
from ..base import CommandAuditTool


class BearerTool(CommandAuditTool):
    """
    Wrapper for Bearer CLI execution.
    
    Bearer scans code for:
    - Sensitive data flows (PII, secrets, etc.)
    - Security vulnerabilities
    - Privacy issues
    - OWASP compliance
    
    Outputs results in JSON format grouped by severity.
    
    Inherits from CommandAuditTool for command execution.
    """
    
    @property
    def name(self) -> str:
        """Tool identifier used in database and CLI."""
        return "bearer"
    
    def __init__(
        self,
        *,
        config_file: Optional[str] = None,
        only_rule: Optional[List[str]] = None,
        skip_rule: Optional[List[str]] = None,
        severity: Optional[str] = None,
        format: str = "json",
        quiet: bool = False,
        disable_default_rules: bool = False,
        extra_args: Optional[List[str]] = None,
        **kw: Any,
    ) -> None:
        """
        Initialize Bearer wrapper.
        
        Parameters
        ----------
        config_file : str, optional
            Path to Bearer configuration file
        only_rule : List[str], optional
            Only run specified rules
        skip_rule : List[str], optional
            Skip specified rules
        severity : str, optional
            Minimum severity level: critical, high, medium, low
        format : str
            Output format (default: json)
        quiet : bool
            Suppress progress output (default: False)
        disable_default_rules : bool
            Disable default security rules (default: False)
        extra_args : List[str], optional
            Additional CLI arguments
        **kw : Any
            Passed to CommandAuditTool (timeout_s, mem_mb, etc.)
        """
        super().__init__(**kw)
        self.config_file = config_file
        self.only_rule = only_rule or []
        self.skip_rule = skip_rule or []
        self.severity = severity
        self.format = format
        self.quiet = quiet
        self.disable_default_rules = disable_default_rules
        self.extra_args = extra_args or []
    
    def build_cmd(self, path: str) -> List[str]:
        """
        Build command-line arguments for Bearer.
        
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
        >>> tool = BearerTool()
        >>> tool.build_cmd("/path/to/code")
        ['bearer', 'scan', '/path/to/code', '-f', 'json', '--quiet']
        """
        cmd: List[str] = ["bearer", "scan", path]
        
        # Output format
        cmd += ["-f", self.format]
        
        # Config file
        if self.config_file:
            cmd += ["--config-file", self.config_file]
        
        # Rule filters
        for rule in self.only_rule:
            cmd += ["--only-rule", rule]
        
        for rule in self.skip_rule:
            cmd += ["--skip-rule", rule]
        
        # Severity filter
        if self.severity:
            cmd += ["--severity", self.severity]
        
        # Disable default rules
        if self.disable_default_rules:
            cmd.append("--disable-default-rules")
        
        # Quiet mode (suppress progress bars)
        if self.quiet:
            cmd.append("--quiet")
        
        # Additional arguments
        cmd += self.extra_args
        
        return cmd
    
    def audit(self, path: str | Path) -> ToolRunResult:
        """
        Run Bearer analysis on the specified path.
        
        Parameters
        ----------
        path : str or Path
            Target file or directory to scan
        
        Returns
        -------
        ToolRunResult
            Standardized result with parsed JSON findings
        
        Notes
        -----
        Bearer returns non-zero exit codes when issues are found.
        Exit code 1 typically means findings were detected, which
        we handle as a successful scan.
        """
        path_str = str(Path(path).resolve())
        cwd_str = str(Path(path_str).parent) if Path(path_str).is_file() else path_str
        
        cmd = self.build_cmd(path_str)
        result = self._run(cmd, cwd=cwd_str)
        
        # Bearer returns non-zero when findings are detected
        # This is expected behavior, not an error
        if result.returncode != 0 and result.stdout:
            # Try to parse JSON from stdout
            try:
                result.parsed_json = json.loads(result.stdout)
            except json.JSONDecodeError:
                # If stdout isn't valid JSON, leave as is
                pass
        
        return result
    
    def parse(self, result: ToolRunResult) -> None:
        """
        Post-process Bearer results.
        
        Parameters
        ----------
        result : ToolRunResult
            Tool execution result
        """
        # Bearer writes JSON to stdout
        # Ensure it's parsed if not already
        if not result.parsed_json and result.stdout:
            try:
                result.parsed_json = json.loads(result.stdout)
            except json.JSONDecodeError:
                # Empty results structure
                result.parsed_json = {
                    "high": [],
                    "medium": [],
                    "low": [],
                    "critical": []
                }
        
        return None


__all__ = ["BearerTool"]
