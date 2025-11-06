"""
Static Analysis Orchestrator

This module orchestrates the execution of multiple static analysis tools
(Bandit, Mypy, Radon, Vulture, ESLint, Semgrep) on source code files and
manages the storage of results in the database.

The orchestrator:
- Discovers appropriate tools for each file type
- Executes tools with proper configuration
- Parses tool output into standardized models
- Stores results in the unified database
- Supports parallel execution for performance

Example:
    Run all tools on a Python file::

        results = audit_file("/path/to/file.py", ["bandit", "mypy"])
        
    Run a single tool directly::
    
        result = run_tool_direct("bandit", "/path/to/file.py")

Author: Anush Krishna
License: MIT
"""
from __future__ import annotations

import re
import json
import os
import shutil
import time
import tempfile
from datetime import datetime
import logging
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Mapping, Sequence, Tuple, Callable, Optional


from auditor.core.models.orm import Base
from auditor.core.models.schema import (
    ToolRunResult,
    bandit_json_to_models,
    eslint_rows_to_models,
    mypy_ndjson_to_models,
    radon_to_models,
    vulture_text_to_models,
    semgrep_to_models,
    gitleaks_json_to_models,
    biome_json_to_models,
    snyk_sarif_to_models,
    bearer_json_to_models,
    qlty_sarif_to_models,
)
from auditor.infra.tools.bandit.base import BanditTool

from auditor.infra.tools.mypy.base import MypyTool
from auditor.infra.tools.radon.base import RadonTool
from auditor.infra.tools.vulture.base import VultureTool
from auditor.infra.tools.semgrep.base import SemgrepTool
from auditor.infra.tools.eslint.base import EslintTool
from auditor.infra.tools.gitleaks.base import GitleaksTool
from auditor.infra.tools.biome.base import BiomeTool
from auditor.infra.tools.snyk.base import SnykTool
from auditor.infra.tools.bearer.base import BearerTool
from auditor.infra.tools.qlty.base import QltyTool

from auditor.infra.db.utils import save_scan_and_rows

# Tool factory registry mapping tool names to their implementation classes
TOOL_FACTORIES = {
    "semgrep": SemgrepTool,
    "bandit": BanditTool,
    "mypy": MypyTool,
    "radon": RadonTool,
    "vulture": VultureTool,
    "eslint": EslintTool,
    "gitleaks": GitleaksTool,
    "biome": BiomeTool,
    "snyk": SnykTool,
    "bearer": BearerTool,
    "qlty": QltyTool,
}


def available_tools() -> List[str]:
    """Get list of available static analysis tools.

    Returns
    -------
    List[str]
        List of tool names that can be instantiated.

    Examples
    --------
    >>> tools = available_tools()
    >>> 'bandit' in tools
    True
    >>> 'mypy' in tools
    True
    """
    return list(TOOL_FACTORIES.keys())


def instantiate_tool(name: str):
    """Instantiate a tool by name from the factory registry.

    Parameters
    ----------
    name : str
        Name of the tool to instantiate (case-insensitive).

    Returns
    -------
    AuditTool
        Instance of the requested tool.

    Raises
    ------
    ValueError
        If the tool name is not recognized.

    Examples
    --------
    >>> tool = instantiate_tool('bandit')
    >>> tool.name
    'bandit'
    """
    try:
        factory = TOOL_FACTORIES[name.lower()]
    except KeyError as exc:  # pragma: no cover - defensive
        raise ValueError(f"Unknown tool '{name}'") from exc
    return factory()


def run_tool_direct(name: str, target: str) -> ToolRunResult:
    """Execute a tool directly and return its result.

    Parameters
    ----------
    name : str
        Name of the tool to run.
    target : str
        Path to file or directory to analyze.

    Returns
    -------
    ToolRunResult
        Standardized tool execution result containing stdout, stderr,
        exit code, and parsed JSON output.

    Raises
    ------
    ValueError
        If tool name is unknown or tool returns no result.
    TypeError
        If tool returns unexpected result type.

    Notes
    -----
    This function handles tools that return either:
    - Direct ToolRunResult objects
    - Tuples containing (findings, ToolRunResult)

    Examples
    --------
    >>> result = run_tool_direct('bandit', 'myfile.py')
    >>> result.tool
    'bandit'
    >>> result.returncode
    0
    """
    tool = instantiate_tool(name)
    run = tool.audit(target)
    if run is None:
        raise ValueError(f"Tool {name} returned no result")
    if isinstance(run, ToolRunResult):
        return run
    # Some tools may return tuple/findings; standardise by reading second value
    if isinstance(run, tuple):
        _, result = run
        return result
    raise TypeError(f"Tool {name} returned unexpected payload: {type(run)!r}")


def parse_to_models(
    result: ToolRunResult, *, radon_bundle: Mapping[str, object] | None = None, start_root: Optional[str] = None
):
    """Parse tool execution result into database models.

    Parameters
    ----------
    result : ToolRunResult
        Raw tool execution result to parse.
    radon_bundle : Mapping[str, object], optional
        Radon metrics bundle for ESLint integration. Default is None.
    start_root : str, optional
        Root path for relative path computation. Default is None.

    Returns
    -------
    tuple of (scan, rows)
        scan : ScanModel or None
            Scan metadata model.
        rows : List
            List of finding/metric row models.

    Raises
    ------
    ValueError
        If tool is not supported.

    Notes
    -----
    Each tool has a specific parser that converts its output format into
    standardized database models. Special cases:
    - ESLint: Skipped for .py files, uses radon_bundle if provided
    - Vulture: Uses minimum confidence threshold of 50

    Examples
    --------
    >>> result = run_tool_direct('bandit', 'test.py')
    >>> scan, rows = parse_to_models(result)
    >>> len(rows) >= 0
    True
    """
    tool = result.tool.lower()
    if tool == "bandit":
        payload = {}
        if isinstance(result.parsed_json, dict):
            payload = result.parsed_json
        scan, rows = bandit_json_to_models(payload.get("results", []), cwd=result.cwd, start_root=start_root)
    elif tool == "mypy":
        # if its not a py file, skip mypy
        if str(result.cwd).endswith(".py"):
            text = (result.stdout or "").strip()
            scan, rows = mypy_ndjson_to_models(text, cwd=result.cwd, start_root=start_root)
        else:
            return None, []
    elif tool == "radon":
        payload = result.parsed_json or {}
        scan, rows = radon_to_models(payload, cwd=result.cwd)
    elif tool == "vulture":
        scan, rows = vulture_text_to_models(
            result.stdout or "", cwd=result.cwd, min_confidence=50, start_root=start_root
        )
    elif tool == "eslint":
        # if py file skip eslint
        if str(result.cwd).endswith(".py"):
            return None, []
        shim = SimpleNamespace(
            parsed_json=result.parsed_json,
            stdout=result.stdout,
            stderr=result.stderr,
            cwd=result.cwd,
            exitcode=result.returncode,
            duration_s=result.duration_s,
            cmd=result.cmd,
        )
        scan, rows = eslint_rows_to_models(shim, radon_bundle=radon_bundle, start_root=start_root)
    elif tool == "semgrep":
        scan, rows = semgrep_to_models(result.parsed_json or {}, cwd=result.cwd, start_root=start_root)
    elif tool == "gitleaks":
        scan, rows = gitleaks_json_to_models(
            result.parsed_json or [],
            cwd=result.cwd,
            start_root=start_root,
            redacted=True
        )
    elif tool == "biome":
        scan, rows = biome_json_to_models(
            result.parsed_json or {},
            cwd=result.cwd,
            start_root=start_root
        )
    elif tool == "snyk":
        scan, rows = snyk_sarif_to_models(
            result.parsed_json or {"runs": []},
            cwd=result.cwd,
            start_root=start_root
        )
    elif tool == "bearer":
        scan, rows = bearer_json_to_models(
            result.parsed_json or {"high": [], "medium": [], "low": [], "critical": []},
            cwd=result.cwd,
            start_root=start_root
        )
    elif tool == "qlty":
        scan, rows = qlty_sarif_to_models(
            result.parsed_json or {"runs": []},
            cwd=result.cwd,
            start_root=start_root
        )
    else:  # pragma: no cover - defensive
        raise ValueError(f"Unsupported tool '{result.tool}'")
    return scan, rows


def parsetomodels(result: ToolRunResult, **kwargs):
    """Legacy alias for parse_to_models.

    Parameters
    ----------
    result : ToolRunResult
        Tool execution result to parse.
    **kwargs
        Additional keyword arguments passed to parse_to_models.

    Returns
    -------
    tuple
        Same as parse_to_models.

    See Also
    --------
    parse_to_models : Primary parsing function
    """
    return parse_to_models(result, **kwargs)


@dataclass
class ToolJob:
    """Job specification for tool execution.

    Attributes
    ----------
    name : str
        Name of the tool to execute.
    target : Path
        Path to file or directory to analyze.
    output : Path
        Path where JSON output will be written.

    Examples
    --------
    >>> job = ToolJob('bandit', Path('src/'), Path('output.json'))
    >>> job.name
    'bandit'
    """

    name: str
    target: Path
    output: Path


def _invoke_run_tool(job: ToolJob) -> Tuple[str, int, str, str, Path]:
    """Invoke a tool as subprocess and return execution details.

    Parameters
    ----------
    job : ToolJob
        Job specification with tool name, target, and output path.

    Returns
    -------
    tuple of (name, returncode, stdout, stderr, output_path)
        name : str
            Tool name.
        returncode : int
            Process exit code.
        stdout : str
            Standard output from process.
        stderr : str
            Standard error from process.
        output_path : Path
            Path where JSON results were written.

    Notes
    -----
    Executes tool via subprocess by calling `python -m auditor run-tool`.
    Output is written to job.output as JSON.
    """
    cmd = [
        sys.executable,
        "-m",
        "auditor",
        "run-tool",
        job.name,
        str(job.target),
        "--json-out",
        str(job.output),
    ]
    # run_tool_direct(
    #     job.name,
    #     str(job.target),
    # )

    proc = subprocess.run(cmd, capture_output=True, text=True)
    return job.name, proc.returncode, proc.stdout, proc.stderr, job.output


def _load_run_result(path: Path) -> ToolRunResult:
    """Load and validate tool execution result from JSON file.

    Parameters
    ----------
    path : Path
        Path to JSON file containing tool result.

    Returns
    -------
    ToolRunResult
        Validated tool execution result.

    Notes
    -----
    Handles legacy field names (parsedjson -> parsed_json) and provides
    sensible defaults for missing fields. Uses Pydantic validation to
    ensure result conforms to ToolRunResult schema.

    Examples
    --------
    >>> result = _load_run_result(Path('bandit-output.json'))
    >>> result.tool
    'bandit'
    """
    with path.open("r", encoding="utf-8") as fh:
        payload = json.load(fh)
    if "parsedjson" in payload and "parsed_json" not in payload:
        payload["parsed_json"] = payload["parsedjson"]
    # Provide sane defaults for missing keys
    payload.setdefault("cmd", [])
    payload.setdefault("cwd", str(Path(payload.get("cwd") or Path.cwd())))
    payload.setdefault("returncode", payload.get("exitcode", 0) or 0)
    payload.setdefault("duration_s", payload.get("duration_s", 0.0))
    payload.setdefault("stdout", payload.get("stdout", ""))
    payload.setdefault("stderr", payload.get("stderr", ""))
    payload.setdefault("parsed_json", payload.get("parsed_json"))
    return ToolRunResult.model_validate(payload)


# ---- helpers ---------------------------------------------------------------


def _slugify(name: str) -> str:
    """Convert name to filesystem-safe slug.

    Parameters
    ----------
    name : str
        Name to slugify.

    Returns
    -------
    str
        Lowercase slug with only alphanumerics, dots, underscores, and hyphens.

    Notes
    -----
    - Converts to lowercase
    - Replaces unsafe characters with hyphens
    - Collapses repeated hyphens
    - Returns 'project' as fallback for empty results

    Examples
    --------
    >>> _slugify('My Project!')
    'my-project'
    >>> _slugify('test__123')
    'test__123'
    """
    # Lowercase, replace non-safe chars with '-', collapse repeats
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", name.strip().lower())
    slug = re.sub(r"-{2,}", "-", slug).strip("-")
    return slug or "project"


def _get_run_id() -> str:
    """Get unique run identifier for this audit session.

    Returns
    -------
    str
        Run ID from AUDIT_RUN_ID environment variable or generated timestamp.

    Notes
    -----
    Format is YYYYMMDD-HHMMSS when auto-generated.

    Examples
    --------
    >>> run_id = _get_run_id()
    >>> len(run_id) == 15  # YYYYMMDD-HHMMSS
    True
    """
    return os.environ.get("AUDIT_RUN_ID") or datetime.now().strftime("%Y%m%d-%H%M%S")


def _setup_run_logging(project_path: Path) -> tuple[logging.Logger, Path]:
    """Setup logging based on DEBUG environment variable.

    Parameters
    ----------
    project_path : Path
        Path to the project being audited.

    Returns
    -------
    tuple[logging.Logger, Path]
        Configured logger and artifacts directory path.

    Notes
    -----
    Logging behavior:
    - If DEBUG env var is not set or is "false": No file logging, NullHandler only
    - If DEBUG="true": Single audit.log file in logs/ directory
    
    This simplified approach avoids creating multiple log directories and
    keeps all logs in a single file for easier management.
    """
    # Create artifacts directory (always needed for tool output)
    artifacts_dir = Path("logs") / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("auditor")
    
    # Check if DEBUG is enabled
    debug_enabled = os.environ.get("DEBUG", "").lower() in ("true", "1", "yes")
    
    if debug_enabled:
        # Only log if DEBUG is enabled
        logger.setLevel(logging.DEBUG)
        
        # Avoid duplicate handlers
        if not any(isinstance(h, logging.FileHandler) for h in logger.handlers):
            log_file = Path("logs") / "audit.log"
            log_file.parent.mkdir(parents=True, exist_ok=True)
            
            fh = logging.FileHandler(log_file, encoding="utf-8", mode='a')
            fh.setFormatter(
                logging.Formatter(
                    "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S"
                )
            )
            logger.addHandler(fh)
            logger.info("=" * 80)
            logger.info("Starting audit for: %s", project_path)
    else:
        # No logging - add NullHandler to suppress warnings
        logger.setLevel(logging.CRITICAL + 1)  # Disable all logging
        if not logger.handlers:
            logger.addHandler(logging.NullHandler())
    
    return logger, artifacts_dir.parent


def _write_text(path: Path, content: str) -> None:
    try:
        path.write_text(content or "", encoding="utf-8", errors="ignore")
    except Exception:
        # Best-effort only; don't break the run due to logging failures
        pass


# ---- main function ---------------------------------------------------------


def _log_event(run_dir: Path, event: str, tool: str, **data: Any) -> None:
    """Append a structured progress event to logs/events.jsonl if DEBUG is enabled.

    Parameters
    ----------
    run_dir : Path
        Base logging directory.
    event : str
        Event type (e.g., 'started', 'finished', 'failed').
    tool : str
        Tool name.
    **data : Any
        Additional event data.

    Notes
    -----
    Only logs events if DEBUG environment variable is set to true.
    Events are written as newline-delimited JSON for easy parsing.
    """
    # Only log events if DEBUG is enabled
    if os.environ.get("DEBUG", "").lower() not in ("true", "1", "yes"):
        return
    
    try:
        rec = {
            "ts": time.time(),
            "timestamp": datetime.now().isoformat(),
            "event": event,
            "tool": tool,
            **data
        }
        events_file = run_dir / "events.jsonl"
        with events_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        # best effort; don't crash on logging issues
        pass


def audit_file(
    project_path: Path,
    tools: Sequence[str],
    jobs: int,
    stop_on_error: bool,
    progress_cb: Optional[Callable[[str, str, Dict[str, Any]], None]] = None,
    start_root: Optional[str] = None,
) -> None:
    """
    Run the given tools for a project with robust file logging.
    progress_cb(event, tool, data) is optional and lets the caller (CLI) show progress bars externally.
    Events: submitted | finished | failed | crashed | parsing_failed |
            processing_started | processing_finished | completed | completed_with_errors
    """
    logger, run_dir = _setup_run_logging(project_path)
    logger.info("Auditing %s", project_path)

    overall_t0 = time.perf_counter()

    def _emit(event: str, tool: str, **data: Any) -> None:
        _log_event(run_dir, event, tool, **data)
        if progress_cb:
            # pass a copy so caller can't mutate our dicts
            progress_cb(event, tool, dict(data))

    with tempfile.TemporaryDirectory(prefix="auditor-") as tmpdir:
        tmpdir_path = Path(tmpdir)
        jobs_to_run = [
            ToolJob(name=tool, target=project_path, output=tmpdir_path / f"{tool}.json")
            for tool in tools
        ]

        logger.info("Running jobs: %s", ", ".join(j.name for j in jobs_to_run))

        max_workers = max(1, min(jobs, len(jobs_to_run)))
        results: Dict[str, ToolRunResult] = {}
        errors: Dict[str, Tuple[int, str]] = {}
        durations: Dict[str, float] = {}

        # Submit all jobs; measure from submission time
        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            future_map = {}
            start_times: Dict[str, float] = {}

            for job in jobs_to_run:
                fut = executor.submit(_invoke_run_tool, job)
                future_map[fut] = job
                start_times[job.name] = time.perf_counter()
                _emit("submitted", job.name, project=str(project_path))

            try:
                for future in as_completed(future_map):
                    job = future_map[future]
                    tool_name = job.name
                    t0 = start_times.get(tool_name, time.perf_counter())

                    try:
                        tool, returncode, stdout, stderr, output_path = future.result()
                    except BaseException as exc:
                        dt = time.perf_counter() - t0
                        durations[tool_name] = dt
                        errors[tool_name] = (-1, repr(exc))
                        logger.exception("%s crashed in %.2fs: %r", tool_name, dt, exc)
                        _emit(
                            "crashed",
                            tool_name,
                            duration_sec=round(dt, 3),
                            error=repr(exc),
                        )
                        if stop_on_error:
                            _flush_summary(
                                run_dir,
                                project_path,
                                tools,
                                results,
                                errors,
                                durations,
                                overall_t0,
                            )
                            # cancel pending
                            for f in future_map:
                                if not f.done():
                                    f.cancel()
                            raise
                        continue

                    dt = time.perf_counter() - t0
                    durations[tool] = dt

                    # Persist raw streams to logs
                    _write_text(run_dir / f"{tool}.out.log", stdout)
                    _write_text(run_dir / f"{tool}.err.log", stderr)

                    if returncode != 0:
                        message = (stderr or stdout or "unknown error").strip()
                        errors[tool] = (returncode, message)
                        logger.warning(
                            "%s failed (exit %s) in %.2fs: %s",
                            tool,
                            returncode,
                            dt,
                            message,
                        )
                        _emit(
                            "failed",
                            tool,
                            duration_sec=round(dt, 3),
                            exit=returncode,
                            message=message,
                        )
                        if stop_on_error:
                            _flush_summary(
                                run_dir,
                                project_path,
                                tools,
                                results,
                                errors,
                                durations,
                                overall_t0,
                            )
                            for f in future_map:
                                if not f.done():
                                    f.cancel()
                            raise RuntimeError(
                                f"{tool} failed (exit {returncode}): {message}"
                            )
                        continue

                    # Copy artifact for debugging (only if DEBUG enabled)
                    if os.environ.get("DEBUG", "").lower() in ("true", "1", "yes"):
                        try:
                            artifacts_dir = run_dir / "artifacts"
                            artifacts_dir.mkdir(exist_ok=True)
                            if output_path and output_path.exists():
                                shutil.copy2(output_path, artifacts_dir / f"{tool}.json")
                        except Exception as copy_exc:
                            logger.warning(
                                "Failed to copy artifact for %s: %s", tool, copy_exc
                            )

                    # Parse and stash
                    try:
                        results[tool] = _load_run_result(output_path)
                        logger.info("%s completed in %.2fs", tool, dt)
                        _emit("finished", tool, duration_sec=round(dt, 3))
                    except Exception as exc:  # pragma: no cover
                        errors[tool] = (returncode, str(exc))
                        logger.warning(
                            "Unable to parse %s output after %.2fs: %s", tool, dt, exc
                        )
                        _emit(
                            "parsing_failed",
                            tool,
                            duration_sec=round(dt, 3),
                            error=str(exc),
                        )
                        if stop_on_error:
                            _flush_summary(
                                run_dir,
                                project_path,
                                tools,
                                results,
                                errors,
                                durations,
                                overall_t0,
                            )
                            for f in future_map:
                                if not f.done():
                                    f.cancel()
                            raise

            except KeyboardInterrupt:
                logger.warning("Interrupted by user; cancelling pending tasks")
                for f in future_map:
                    if not f.done():
                        f.cancel()
                raise

        # Optional radon bundle
        radon_bundle: Mapping[str, Any] | None = None
        radon_result = results.get("radon")
        if radon_result and isinstance(radon_result.parsed_json, Mapping):
            radon_bundle = radon_result.parsed_json

        # Persist results into DB
        for tool in tools:
            logger.info("Processing results for %s", tool)
            _emit("processing_started", tool, project=str(project_path))
            if tool not in results:
                continue
            run_result = results[tool]
            if tool == "eslint":
                scan, rows = parse_to_models(run_result, radon_bundle=radon_bundle, start_root=str(start_root))
            else:
                scan, rows = parse_to_models(run_result, start_root=str(start_root))
            _, count = save_scan_and_rows(Base, scan, rows)
            logger.info("%s wrote 1 scan row, %d result rows", tool, count)
            _emit("processing_finished", tool, rows=count)

        # Final summary & timing
        _flush_summary(
            run_dir, project_path, tools, results, errors, durations, overall_t0
        )

        if errors and not stop_on_error:
            err_str = ", ".join(f"{k}(exit {v[0]})" for k, v in errors.items())
            logger.info("Completed with errors: %s", err_str)
            _emit("completed_with_errors", "__all__", errors=list(errors.keys()))
        else:
            logger.info("Completed successfully.")
            _emit("completed", "__all__", errors=[])


# ---- summary writer --------------------------------------------------------


def _flush_summary(
    run_dir: Path,
    project_path: Path,
    tools: Sequence[str],
    results: Dict[str, "ToolRunResult"],
    errors: Dict[str, Tuple[int, str]],
    durations: Dict[str, float],
    overall_t0: float,
) -> None:
    """Write execution summary to logs/summary.json if DEBUG is enabled.

    Parameters
    ----------
    run_dir : Path
        Base logging directory.
    project_path : Path
        Path to audited project.
    tools : Sequence[str]
        List of requested tools.
    results : Dict[str, ToolRunResult]
        Successfully completed tool results.
    errors : Dict[str, Tuple[int, str]]
        Failed tools with exit code and message.
    durations : Dict[str, float]
        Execution time for each tool.
    overall_t0 : float
        Start time for overall execution.

    Notes
    -----
    Only writes summary if DEBUG environment variable is set to true.
    Summary includes timing information and success/failure status.
    """
    # Only write summary if DEBUG is enabled
    if os.environ.get("DEBUG", "").lower() not in ("true", "1", "yes"):
        return
    
    try:
        summary = {
            "timestamp": datetime.now().isoformat(),
            "project": str(project_path),
            "tools_requested": list(tools),
            "tools_ok": sorted(results.keys()),
            "tools_failed": {
                k: {"exit": v[0], "message": v[1]} for k, v in errors.items()
            },
            "durations_sec": {k: round(v, 3) for k, v in durations.items()},
            "elapsed_total_sec": round(time.perf_counter() - overall_t0, 3),
            "artifacts_dir": str((run_dir / "artifacts").resolve()),
        }
        summary_file = run_dir / "summary.json"
        summary_file.write_text(
            json.dumps(summary, indent=2), encoding="utf-8"
        )
    except Exception as exc:
        # Never fail the run due to logging/summary issues
        logging.getLogger(__name__).warning("Failed to write summary.json: %s", exc)


__all__ = [
    "available_tools",
    "instantiate_tool",
    "run_tool_direct",
    "audit_file",
    "parse_to_models",
    "parsetomodels",
]
