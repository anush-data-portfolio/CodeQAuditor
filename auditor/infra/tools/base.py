"""Base classes for static analysis tool wrappers.

This module provides abstract base classes for wrapping external static analysis
tools. All tool implementations inherit from AuditTool and provide standardized
interfaces for execution, timeout handling, and result parsing.

The module supports:
- Command-based tool execution with timeout and resource limits
- Automatic tool detection and validation
- Standardized result format (ToolRunResult)
- POSIX-specific resource limits (memory, CPU)

Examples
--------
Implement a custom tool:

    >>> class MyTool(AuditTool):
    ...     @property
    ...     def name(self) -> str:
    ...         return 'mytool'
    ...     def audit(self, path):
    ...         # Implementation here
    ...         pass

Notes
-----
Resource limits (memory, CPU) are only enforced on POSIX systems. Windows
systems will ignore these limits.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, List, Optional, Sequence, Union, cast, Dict

from auditor.core.models import ToolRunResult

_IS_POSIX = os.name == "posix"
if _IS_POSIX:
    import resource  # type: ignore[attr-defined]

# ---------------------------------------------------------------------------
# Base tool wrappers
# ---------------------------------------------------------------------------


class AuditTool(ABC):
    """Base class for all static analysis tool wrappers.

    This abstract class defines the interface that all tool implementations
    must follow. Subclasses must implement name (property), audit method,
    and optionally build_cmd for command-based tools.

    Parameters
    ----------
    timeout_s : int, optional
        Process timeout in seconds. Default is DEFAULT_TIMEOUT_S (300).
    mem_mb : int, optional
        Memory limit in megabytes (POSIX only). Default is None (no limit).
    cpus : int, optional
        CPU count hint (not enforced). Default is None.
    env : Dict[str, str], optional
        Additional environment variables. Default is None.

    Attributes
    ----------
    DEFAULT_TIMEOUT_S : int
        Default per-process time limit in seconds (300).
    DEFAULT_MEM_MB : int or None
        Default memory limit in MB (None = no limit).
    DEFAULT_CPUS : int or None
        Default CPU count hint (not enforced).

    Notes
    -----
    The class automatically sets PYTHONUNBUFFERED=1 and PYTHONWARNINGS=ignore
    in the environment to ensure clean tool output.

    Memory and CPU limits are advisory and may not be strictly enforced
    depending on the platform and tool implementation.

    Examples
    --------
    >>> tool = MyCustomTool(timeout_s=600, mem_mb=2048)
    >>> result = tool.audit('/path/to/code')
    >>> result.returncode
    0
    """

    #: default per-process time limit (seconds)
    DEFAULT_TIMEOUT_S: int = 300
    #: default memory limit in MB (None to disable)
    DEFAULT_MEM_MB: Optional[int] = None
    #: default CPU count hint (not enforced; use Docker/cgroups for hard caps)
    DEFAULT_CPUS: Optional[int] = None

    def __init__(
        self,
        timeout_s: Optional[int] = None,
        mem_mb: Optional[int] = None,
        cpus: Optional[int] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> None:
        self.timeout_s = timeout_s or self.DEFAULT_TIMEOUT_S
        self.mem_mb = mem_mb if mem_mb is not None else self.DEFAULT_MEM_MB
        self.cpus = cpus if cpus is not None else self.DEFAULT_CPUS
        self.env = {
            **os.environ,
            "PYTHONUNBUFFERED": "1",
            "PYTHONWARNINGS": "ignore",
        }
        if env:
            self.env.update(env)

    # ----- Properties to override -------------------------------------------------

    @property
    @abstractmethod
    def name(self) -> str:
        """Get the tool name identifier.

        Returns
        -------
        str
            Lowercase tool name (e.g., 'bandit', 'mypy', 'eslint').

        Notes
        -----
        This property must be implemented by all subclasses.
        """
        raise NotImplementedError

    # ----- Public API -------------------------------------------------------------

    def is_installed(self) -> bool:
        """Check if the tool is installed and available on the system.

        Returns
        -------
        bool
            True if tool executable is found in PATH, False otherwise.

        Notes
        -----
        Uses build_cmd to determine executable name and checks via shutil.which.

        Examples
        --------
        >>> tool = BanditTool()
        >>> tool.is_installed()
        True
        """
        exe = self._exe_from_cmd(self.build_cmd("."))
        return shutil.which(exe) is not None

    @abstractmethod
    def audit(self, path: Union[str, Path]) -> ToolRunResult:
        """Run the analyzer against path and return results.

        Parameters
        ----------
        path : str or Path
            File or directory path to analyze.

        Returns
        -------
        ToolRunResult
            Standardized result containing stdout, stderr, exit code,
            execution time, and parsed JSON output.

        Notes
        -----
        This method must be implemented by all subclasses. It should handle
        tool execution, output capture, and result packaging.

        Examples
        --------
        >>> tool = BanditTool()
        >>> result = tool.audit('myproject/')
        >>> result.returncode
        0
        """
        raise NotImplementedError

    def build_cmd(self, path: str) -> List[str]:
        """Build command-line arguments for tool execution.

        Parameters
        ----------
        path : str
            Target path to analyze.

        Returns
        -------
        List[str]
            Command and arguments as list of strings.

        Notes
        -----
        Optional helper that command-based tools should implement.
        Used by is_installed and CommandAuditTool base class.

        Examples
        --------
        >>> tool = BanditTool()
        >>> tool.build_cmd('src/')
        ['bandit', '-r', '-f', 'json', 'src/']
        """
        raise NotImplementedError

    def parse(self, result: ToolRunResult) -> None:
        """Post-process tool execution results.

        Parameters
        ----------
        result : ToolRunResult
            Raw tool execution result.

        Returns
        -------
        None
            Default implementation is a no-op.

        Notes
        -----
        Hook for subclasses to perform additional parsing or validation.
        Override this method to add custom post-processing logic.
        """
        return None

    # ----- Utilities --------------------------------------------------------------

    def _exe_from_cmd(self, cmd: Sequence[str]) -> str:
        # First token can be "python -m tool" or just "ruff"
        first = cmd[0]
        if first == sys.executable and len(cmd) >= 3 and cmd[1] == "-m":
            return cmd[2]
        return first

    def _preexec_limits(self) -> Optional[Any]:
        if not _IS_POSIX:
            return None

        def _apply():
            # Soft/hard RLIMIT_AS in bytes to approximate memory cap
            if self.mem_mb:
                bytes_limit = int(self.mem_mb) * 1024 * 1024
                resource.setrlimit(resource.RLIMIT_AS, (bytes_limit, bytes_limit))
            # Disable core dumps
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

        return _apply

    def _run(self, cmd: Sequence[str], cwd: Optional[str] = None) -> ToolRunResult:
        started = time.time()
        try:
            proc = subprocess.run(
                cmd,
                cwd=cwd,
                env=self.env,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.timeout_s,
                preexec_fn=self._preexec_limits(),
            )
        except subprocess.TimeoutExpired as e:
            # Synthesize a result on timeout
            duration = time.time() - started
            stdout = e.stdout
            if isinstance(stdout, bytes):
                stdout = stdout.decode("utf-8", "ignore")
            stderr = e.stderr
            if isinstance(stderr, bytes):
                stderr = stderr.decode("utf-8", "ignore")
            return ToolRunResult(
                tool=self.name,
                cmd=list(cmd),
                cwd=os.path.abspath(cwd or os.getcwd()),
                returncode=124,
                duration_s=duration,
                stdout=stdout or "",
                stderr=(stderr or "") + f"\n[TIMEOUT after {self.timeout_s}s]",
                parsed_json=None,
            )
        duration = time.time() - started
        stdout_raw = cast(Optional[str], proc.stdout)
        stderr_raw = cast(Optional[str], proc.stderr)
        stdout = stdout_raw or ""
        stderr = stderr_raw or ""

        parsed = None
        # Best-effort JSON parse if it looks like JSON
        txt = stdout.strip()
        if txt.startswith("{") or txt.startswith("["):
            try:
                parsed = json.loads(txt)
            except Exception:
                parsed = None

        return ToolRunResult(
            tool=self.name,
            cmd=list(cmd),
            cwd=os.path.abspath(cwd or os.getcwd()),
            returncode=proc.returncode,
            duration_s=duration,
            stdout=stdout,
            stderr=stderr,
            parsed_json=parsed,
        )


class CommandAuditTool(AuditTool):
    """
    Convenience base class for tools that execute a single command and optionally
    post-process its output via `parse`.
    """

    def audit(self, path: Union[str, Path]) -> ToolRunResult:
        path_str = str(Path(path).resolve())
        cwd_str = str(Path(path_str).parent)
        cmd = self.build_cmd(path_str)
        print(cmd)
        run = self._run(cmd, cwd=cwd_str)
        print(f"[DEBUG] Ran command: {' '.join(cmd)}")
        print(f"[DEBUG] Return code: {run.returncode}")
        return run


class NodeToolMixin:
    """
    Run Node-based CLIs from a *central* cache (no install in target repos).
    Assumes a layout like:
      <repo_root>/script_tool_cache/{node_modules, eslint.config.mjs, package.json}

    Env overrides:
      AUDIT_NODE_CACHE: absolute path to that folder (optional)
    """

    def _node_prefix(self) -> Path:
        # Default: <repo_root>/script_tool_cache relative to this file
        env = os.environ.get("AUDIT_NODE_CACHE")
        if env:
            return Path(env).expanduser().resolve()
        # auditor/tools/tsx/nodejs.py → repo_root/node_tools
        return Path(__file__).resolve().parents[3] / "node_tools"

    def _node_bin(self, exe: str) -> Path:
        return self._node_prefix() / "node_modules" / ".bin" / exe

    def _prepare_node_env(self) -> None:
        """Augment self.env so node resolves binaries/plugins from central cache."""
        prefix = self._node_prefix()
        bin_dir = prefix / "node_modules" / ".bin"
        node_modules = prefix / "node_modules"

        # PATH: ensure the central .bin is first
        prev_path = self.env.get("PATH", "")
        self.env["PATH"] = (
            f"{bin_dir}{os.pathsep}{prev_path}" if prev_path else str(bin_dir)
        )

        # NODE_PATH: help resolvers (plugins/parsers) load from the central cache
        prev_np = self.env.get("NODE_PATH", "")
        self.env["NODE_PATH"] = (
            f"{node_modules}{os.pathsep}{prev_np}" if prev_np else str(node_modules)
        )

        # ESLint flat config (central eslint.config.mjs)
        self.env.setdefault("ESLINT_USE_FLAT_CONFIG", "true")

        # Hardening: no network installs (we don't call npx, but be explicit)
        self.env.setdefault("NPM_CONFIG_AUDIT", "false")
        self.env.setdefault("NPM_CONFIG_FUND", "false")
        self.env.setdefault("NPM_CONFIG_UPDATE_NOTIFIER", "false")

    def _node_cmd(
        self,
        *,
        exe: str,
        cwd: Union[str, Path, None] = None,
        npm_package: Optional[str] = None,
        version: Optional[str] = None,
        subcommand: Sequence[str] | None = None,
        extra: Sequence[str] | None = None,
    ) -> List[str]:
        """
        Compose a command that invokes a central binary directly.
        We avoid npx to guarantee offline, deterministic execution.
        """
        # Accept but ignore npm_package/version so callers can share signature
        # with mixins that still rely on npx-style execution.
        _ = npm_package, version

        bin_path = self._node_bin(exe)
        if not bin_path.exists():
            raise FileNotFoundError(
                f"Missing {exe} at {bin_path}. Ensure node_tools/node_modules is populated."
            )
        cmd: List[str] = [str(bin_path)]
        if subcommand:
            cmd += list(subcommand)
        if extra:
            cmd += list(extra)
        return cmd
