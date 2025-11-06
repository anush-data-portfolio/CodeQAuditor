"""Gitleaks secret scanning tool implementation.

This module implements the Gitleaks tool wrapper for detecting hardcoded
secrets, passwords, API keys, and tokens in source code.

Classes
-------
GitleaksTool : Gitleaks tool implementation

Examples
--------
>>> tool = GitleaksTool()
>>> if tool.is_installed():
...     result = tool.audit("/path/to/code")

See Also
--------
auditor.infra.tools.base : Base tool class
auditor.core.models.parsers.gitleaks : Result parser
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, List, Optional

from auditor.core.models import ToolRunResult
from ..base import CommandAuditTool


class GitleaksTool(CommandAuditTool):
    """
    Wrapper for Gitleaks CLI execution.
    
    Gitleaks scans for hardcoded secrets in:
    - Git repositories
    - Local directories
    - Individual files
    - Stdin input
    
    Inherits from CommandAuditTool for command execution.
    """
    
    @property
    def name(self) -> str:
        """Tool identifier used in database and CLI."""
        return "gitleaks"
    
    def __init__(
        self,
        *,
        redact: bool = True,
        no_git: bool = True,
        baseline_path: Optional[str] = None,
        config_path: Optional[str] = None,
        verbose: bool = False,
        max_target_megabytes: Optional[int] = None,
        log_level: str = "warn",
        extra_args: Optional[List[str]] = None,
        **kw: Any,
    ) -> None:
        """
        Initialize Gitleaks wrapper.
        
        Parameters
        ----------
        redact : bool
            Redact secrets from output (default: True for safety)
        no_git : bool
            Scan directory as regular files, not git repo (default: True)
        baseline_path : str, optional
            Path to baseline file with issues to ignore
        config_path : str, optional
            Path to custom Gitleaks config file
        verbose : bool
            Show verbose output (default: False)
        max_target_megabytes : int, optional
            Skip files larger than this size
        log_level : str
            Log level: trace, debug, info, warn, error, fatal (default: warn)
        extra_args : List[str], optional
            Additional CLI arguments
        **kw : Any
            Passed to CommandAuditTool (timeout_s, mem_mb, etc.)
        """
        super().__init__(**kw)
        self.redact = redact
        self.no_git = no_git
        self.baseline_path = baseline_path
        self.config_path = config_path
        self.verbose = verbose
        self.max_target_megabytes = max_target_megabytes
        self.log_level = log_level
        self.extra_args = extra_args or []
    
    def build_cmd(self, path: str) -> List[str]:
        """
        Build command-line arguments for Gitleaks.
        
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
        >>> tool = GitleaksTool()
        >>> tool.build_cmd("/path/to/code")
        ['gitleaks', 'detect', '--source', '/path/to/code', '--report-format', 'json', ...]
        """
        cmd: List[str] = ["gitleaks", "detect"]
        
        # Source path
        cmd += ["--source", path]
        
        # Output format (always JSON for parsing)
        cmd += ["--report-format", "json"]
        
        # Redact secrets for safety
        if self.redact:
            cmd.append("--redact")
        
        # Treat as regular directory (not git repo)
        if self.no_git:
            cmd.append("--no-git")
        
        # Baseline file
        if self.baseline_path:
            cmd += ["--baseline-path", self.baseline_path]
        
        # Custom config
        if self.config_path:
            cmd += ["--config", self.config_path]
        
        # File size limit
        if self.max_target_megabytes:
            cmd += ["--max-target-megabytes", str(self.max_target_megabytes)]
        
        # Logging
        cmd += ["--log-level", self.log_level]
        
        # Verbose output
        if self.verbose:
            cmd.append("--verbose")
        
        # Suppress banner for clean output
        cmd.append("--no-banner")
        
        # Additional arguments
        cmd += self.extra_args
        
        return cmd
    
    def audit(self, path: str | Path) -> ToolRunResult:
        """
        Run Gitleaks analysis on the specified path.
        
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
        Gitleaks returns exit code 1 when leaks are found, which is expected
        behavior. We handle this gracefully.
        """
        path_str = str(Path(path).resolve())
        cwd_str = str(Path(path_str).parent) if Path(path_str).is_file() else path_str
        
        cmd = self.build_cmd(path_str)
        result = self._run(cmd, cwd=cwd_str)
        
        # Gitleaks returns exit code 1 when leaks are found
        # This is expected behavior, not an error
        if result.returncode == 1 and result.stdout:
            # Try to parse JSON from stdout
            try:
                result.parsed_json = json.loads(result.stdout)
            except json.JSONDecodeError:
                # If stdout isn't JSON, leave parsed_json as is
                pass
        
        return result
    
    def parse(self, result: ToolRunResult) -> None:
        """
        Post-process Gitleaks results.
        
        Parameters
        ----------
        result : ToolRunResult
            Tool execution result
        """
        # Gitleaks writes JSON to stdout
        # Ensure it's parsed if not already
        if not result.parsed_json and result.stdout:
            try:
                result.parsed_json = json.loads(result.stdout)
            except json.JSONDecodeError:
                result.parsed_json = []
        
        return None


__all__ = ["GitleaksTool"]
