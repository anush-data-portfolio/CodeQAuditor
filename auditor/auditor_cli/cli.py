"""CodeQAuditor CLI - Command Line Interface.

This module provides the command-line interface for CodeQAuditor, a comprehensive
static analysis orchestration tool. It allows users to run multiple static analysis
tools on their codebase and store results in a unified database.

Synopsis
--------
The CLI supports three main commands:

seed-db
    Initialize the database schema
audit
    Run static analysis tools on a project
export
    Export findings from database to JSON
run-tool
    Run a single tool directly

Options
-------
Common options available across commands:
    --help
        Show help message and exit

audit command options:
    --tool, -t
        Specify which tools to run (default: all available)
    --jobs, -j
        Maximum parallel jobs (default: 4)
    --parallel, -p
        Parallelization strategy: auto, thread, process, none
    --stop-on-error
        Stop execution on first tool failure
    --debug
        Enable debug logging

export command options:
    --output-path, -o
        Directory path for exported JSON files
    --metabob-analysis-path, -m
        Optional Metabob analysis JSON to include

run-tool command options:
    tool
        Name of the tool to run
    target
        Target file or directory
    --json-out
        Write JSON payload to specified path

Examples
--------
Initialize database:
    $ python -m auditor seed-db

Run all tools on a project:
    $ python -m auditor audit /path/to/project

Run specific tools:
    $ python -m auditor audit /path/to/project --tool bandit --tool mypy

Export findings:
    $ python -m auditor export --output-path ./results

Run single tool:
    $ python -m auditor run-tool bandit /path/to/file.py

Notes
-----
The database location and other settings are controlled via the config module.
Progress bars are displayed using tqdm when analyzing multiple projects.

See Also
--------
auditor.application.orchestrator : Tool orchestration logic
auditor.infra.db.seed : Database initialization

Author: Anush Krishna
License: MIT
"""
from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import List, Optional
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from threading import Lock
import json

import typer
from tqdm import tqdm
from config import CONFIG
from auditor.infra.db.seed import seed_database
from auditor.core.models.orm import Base
from auditor.application.extractor import extract_findings_to_json, metabob_to_auditor

from auditor.application.orchestrator import (
    available_tools,
    audit_file,
    run_tool_direct,
)
from auditor.application.file import discover_files
from enum import Enum


app = typer.Typer(
    help="CodeQAuditor CLI - Multi-tool static analysis orchestration",
    add_completion=False
)

def create_db_path_if_missing(db_path: Path) -> None:
    """Create database directory if it doesn't exist.

    Parameters
    ----------
    db_path : Path
        Path to the database file.

    Notes
    -----
    Creates all parent directories recursively if needed. This is a safe
    operation that will not fail if directories already exist.

    Examples
    --------
    >>> from pathlib import Path
    >>> db_path = Path("./data/db/audit.db")
    >>> create_db_path_if_missing(db_path)
    """
    if not db_path.parent.exists():
        db_path.parent.mkdir(parents=True, exist_ok=True)


def check_database_ready(create: bool = False) -> bool:
    """Check if the database exists and is ready for use.

    Parameters
    ----------
    create : bool, optional
        If True, create database directory if missing. Default is False.

    Returns
    -------
    bool
        True if database file exists, False otherwise.

    Notes
    -----
    The database path is extracted from CONFIG.database_url which should be
    in SQLite URL format (sqlite:///path/to/db).

    Examples
    --------
    >>> check_database_ready(create=True)
    True
    >>> check_database_ready()
    False
    """
    db_path = Path(CONFIG.database_url.replace("sqlite:///", ""))
    if create:
        create_db_path_if_missing(db_path)
    return db_path.exists()


@app.command("seed-db")
def seed_db() -> None:
    """Initialize the database schema.

    Creates the database and all necessary tables if they don't exist.
    This command is idempotent - it's safe to run multiple times.

    Notes
    -----
    The database location is determined by CONFIG.database_url from the
    configuration module. If the database already exists, this command
    will exit without making changes.

    Examples
    --------
    Initialize database from command line:
        $ python -m auditor seed-db

    Expected output:
        Database already exists and is ready.

    Or if creating new database:
        Database seeded successfully.
    """
    if check_database_ready():
        typer.echo("Database already exists and is ready.")
        return
    seed_database(Base)

@app.command("export")
def extract_findings(
    output_path: str = typer.Option(
        ..., "--output-path", "-o", help="Path to write extracted findings JSON"
    ),
    root: Optional[str] = typer.Option(
        None, "--root", "-r", help="Filter by root path or folder name (e.g., 'project_01' or 'data/project_01')"
    ),
    metabob_analysis_path: Optional[str] = typer.Option(
        None, "--metabob-analysis-path", "-m", help="Path to Metabob analysis JSON"
    ),
    interactive: bool = typer.Option(
        False, "--interactive", "-i", help="Interactively select root from available options"
    ),
) -> None:
    """Export findings from the database to JSON format.

    Extracts analysis results from the database and writes them to JSON files.
    Optionally filter by root path and include Metabob analysis results.

    Parameters
    ----------
    output_path : str
        Directory path where JSON files will be written.
    root : str, optional
        Filter findings by root path. Can be:
        - Full path: /home/user/project_01
        - Folder name: project_01
        - Partial path: data/project_01
        If None or not provided, exports all findings. Default is None.
    metabob_analysis_path : str, optional
        Path to Metabob analysis JSON to include. Default is None.
    interactive : bool
        If True, show a list of available roots to choose from. Default is False.

    Raises
    ------
    typer.Exit
        With code 1 if database is not ready or Metabob path doesn't exist.

    Notes
    -----
    Creates the output directory if it doesn't exist. The exported files are:
    - auditor-findings.json: All findings from the database
    - metabob-analysis.json: Converted Metabob results (if provided)

    Examples
    --------
    Export all findings:
        $ python -m auditor export --output-path ./results

    Export findings from specific root:
        $ python -m auditor export -o ./results --root project_01

    Interactive root selection:
        $ python -m auditor export -o ./results --interactive

    Export with Metabob analysis:
        $ python -m auditor export -o ./results -m ./metabob.json

    Expected output:
        Filtered by root: /full/path/to/project_01
        Extracted 42 findings to ./results
    """
    if not check_database_ready():
        typer.echo("Database is not ready. Please seed the database first.", err=True)
        raise typer.Exit(code=1)

    # Import here to avoid circular dependency
    from auditor.application.extractor import get_all_roots, match_root_by_folder
    
    # Handle interactive mode
    selected_root = root
    if interactive or (not root and typer.confirm("Would you like to filter by root?")):
        available_roots = get_all_roots()
        
        if not available_roots:
            typer.echo("No roots found in database.", err=True)
            if not typer.confirm("Export all findings without root filter?"):
                raise typer.Exit(code=0)
        else:
            typer.echo("\nAvailable roots in database:")
            typer.echo("=" * 60)
            
            # Display roots with shortened names for readability
            for idx, root_path in enumerate(available_roots, 1):
                folder_name = root_path.rstrip('/').split('/')[-1]
                typer.echo(f"  {idx}. {folder_name}")
                typer.echo(f"     └─ {root_path}")
            
            typer.echo(f"\n  0. All roots (no filter)")
            typer.echo("=" * 60)
            
            choice = typer.prompt(
                "\nSelect a root by number (or enter folder name/path)",
                default="0"
            )
            
            # Handle numeric choice
            if choice.isdigit():
                choice_idx = int(choice)
                if choice_idx == 0:
                    selected_root = None
                    typer.echo("✓ No root filter applied - exporting all findings")
                elif 1 <= choice_idx <= len(available_roots):
                    selected_root = available_roots[choice_idx - 1]
                    typer.echo(f"✓ Selected root: {selected_root}")
                else:
                    typer.echo(f"Invalid choice: {choice_idx}", err=True)
                    raise typer.Exit(code=1)
            else:
                # Handle text input
                matched = match_root_by_folder(choice, available_roots)
                if matched:
                    selected_root = matched
                    typer.echo(f"✓ Matched root: {selected_root}")
                else:
                    typer.echo(f"No match found for: {choice}", err=True)
                    typer.echo("Available folder names: " + ", ".join(
                        [r.rstrip('/').split('/')[-1] for r in available_roots]
                    ))
                    raise typer.Exit(code=1)
    
    # Resolve root if provided via command line
    elif root:
        available_roots = get_all_roots()
        matched = match_root_by_folder(root, available_roots)
        if matched:
            selected_root = matched
            typer.echo(f"✓ Matched root: {selected_root}")
        else:
            typer.echo(f"Warning: Root '{root}' not found in database, using as-is", err=True)
            selected_root = root

    output_path = Path(output_path)
    
    # If filtering by specific root, export to subfolder
    if selected_root:
        # Extract findings for specific root
        findings = extract_findings_to_json(root=selected_root)
        
        # Create subfolder with root's folder name
        root_folder_name = selected_root.rstrip('/').split('/')[-1]
        root_output_path = output_path / root_folder_name
        root_output_path.mkdir(parents=True, exist_ok=True)
        
        # Save findings
        findings_file = root_output_path / "auditor-findings.json"
        with open(findings_file, "w", encoding="utf-8") as f:
            json.dump(findings, f, ensure_ascii=False, indent=2)

        # Display summary
        typer.echo("\n" + "=" * 60)
        typer.echo(f"Root filter: {findings['root']}")
        typer.echo(f"Root folder: {root_folder_name}/")
        typer.echo(f"Findings extracted: {len(findings['findings'])}")
        typer.echo(f"Output location: {findings_file}")
        typer.echo("=" * 60)
        
    else:
        # Export all roots, each in its own subfolder
        available_roots = get_all_roots()
        
        if not available_roots:
            typer.echo("No roots found in database.", err=True)
            raise typer.Exit(code=1)
        
        typer.echo("\n" + "=" * 60)
        typer.echo(f"Exporting all roots ({len(available_roots)} total)")
        typer.echo("=" * 60)
        
        total_findings = 0
        for root in available_roots:
            # Extract findings for this root
            findings = extract_findings_to_json(root=root)
            
            if not findings['findings']:
                continue  # Skip roots with no findings
            
            # Create subfolder with root's folder name
            root_folder_name = root.rstrip('/').split('/')[-1]
            root_output_path = output_path / root_folder_name
            root_output_path.mkdir(parents=True, exist_ok=True)
            
            # Save findings
            findings_file = root_output_path / "auditor-findings.json"
            with open(findings_file, "w", encoding="utf-8") as f:
                json.dump(findings, f, ensure_ascii=False, indent=2)
            
            typer.echo(f"  ✓ {root_folder_name}: {len(findings['findings'])} findings")
            total_findings += len(findings['findings'])
        
        typer.echo("=" * 60)
        typer.echo(f"Total findings exported: {total_findings}")
        typer.echo(f"Output directory: {output_path}")
        typer.echo("=" * 60)

    # Handle Metabob analysis if provided
    if metabob_analysis_path:
        if selected_root:
            # Save Metabob in the same root-specific folder
            metabob_path = Path(metabob_analysis_path)
            if not metabob_path.exists():
                typer.echo(f"Metabob analysis path {metabob_analysis_path} does not exist.", err=True)
                raise typer.Exit(code=1)
            with open(metabob_path, "r", encoding="utf-8") as f:
                metabob_data = json.load(f)

            metabob_converted = metabob_to_auditor(metabob_data)
            root_folder_name = selected_root.rstrip('/').split('/')[-1]
            root_output_path = output_path / root_folder_name
            metabob_file = root_output_path / "metabob-analysis.json"
            with open(metabob_file, "w", encoding="utf-8") as f:
                json.dump(metabob_converted, f, ensure_ascii=False, indent=2)
            typer.echo(f"✓ Metabob analysis saved to {metabob_file}")
        else:
            typer.echo("Warning: Metabob export only supported with specific root filter", err=True)

@app.command("run-tool")
def run_tool(
    tool: str,
    target: str,
    json_out: Optional[str] = typer.Option(
        None, "--json-out", help="Write JSON payload to this path"
    ),
) -> None:
    """Run a single static analysis tool directly.

    Executes the specified tool on the target path and outputs results either
    to stdout or to a JSON file.

    Parameters
    ----------
    tool : str
        Name of the tool to run (e.g., 'bandit', 'mypy', 'eslint').
    target : str
        Path to file or directory to analyze.
    json_out : str, optional
        Path where JSON payload will be written. If None, outputs to stdout.

    Notes
    -----
    This command bypasses database storage and returns raw tool output.
    Useful for debugging or standalone tool execution.

    The returned JSON includes:
    - tool: Tool name
    - cmd: Command executed
    - cwd: Working directory
    - exitcode: Tool exit code
    - stdout: Standard output
    - stderr: Standard error
    - parsed_json: Parsed tool output (if available)
    - duration_s: Execution time in seconds

    Examples
    --------
    Run Bandit on a file:
        $ python -m auditor run-tool bandit myfile.py

    Save output to JSON:
        $ python -m auditor run-tool mypy src/ --json-out mypy-results.json
    """
    try:
        result = run_tool_direct(tool, target)
    except Exception as exc:  # pragma: no cover - propagated to caller
        payload = {
            "tool": tool,
            "cwd": target,
            "exitcode": 1,
            "returncode": 1,
            "stdout": "",
            "stderr": str(exc),
            "parsedjson": None,
            "parsed_json": None,
            "cmd": [],
            "duration_s": 0.0,
        }
    else:
        payload = {
            "tool": result.tool,
            "cmd": result.cmd,
            "cwd": result.cwd,
            "exitcode": result.returncode,
            "returncode": result.returncode,
            "duration_s": result.duration_s,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "parsed_json": result.parsed_json,
            "parsedjson": result.parsed_json,
        }

    if json_out:
        out_path = Path(json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    else:
        typer.echo(json.dumps(payload, ensure_ascii=False))


class Parallel(str, Enum):
    """Parallelization strategy options for audit execution.

    Attributes
    ----------
    auto : str
        Automatically choose best strategy (defaults to thread).
    thread : str
        Use thread-based parallelization (ThreadPoolExecutor).
    process : str
        Use process-based parallelization (ProcessPoolExecutor).
    none : str
        Sequential execution without parallelization.

    Notes
    -----
    Thread-based parallelization is generally preferred for I/O-bound tasks
    like running external tools and file operations. Process-based is useful
    for CPU-intensive workloads but has pickling overhead.
    """

    auto = "auto"
    thread = "thread"
    process = "process"
    none = "none"


def _choose_executor(kind: Parallel, workers: int):
    """Choose appropriate executor based on parallelization strategy.

    Parameters
    ----------
    kind : Parallel
        Parallelization strategy (auto, thread, process, none).
    workers : int
        Maximum number of parallel workers.

    Returns
    -------
    ThreadPoolExecutor or ProcessPoolExecutor or None
        Executor instance for parallel execution, or None for sequential.

    Notes
    -----
    Auto mode defaults to ThreadPoolExecutor as it's better suited for
    subprocess-heavy and file I/O workloads typical in static analysis.

    Examples
    --------
    >>> executor = _choose_executor(Parallel.thread, 4)
    >>> type(executor).__name__
    'ThreadPoolExecutor'
    """
    if kind == Parallel.thread:
        return ThreadPoolExecutor(max_workers=workers)
    if kind == Parallel.process:
        return ProcessPoolExecutor(max_workers=workers)
    if kind == Parallel.auto:
        # default to threads; better for subprocess/file-heavy work
        return ThreadPoolExecutor(max_workers=workers)
    return None


def _run_one(
    project: Path,
    selected_tools: List[str],
    inner_jobs: int,
    stop_on_error: bool,
    progress_cb=None,
    start_root: Optional[str] = None,
):
    """Execute analysis tools on a single project.

    Parameters
    ----------
    project : Path
        Path to the project directory to analyze.
    selected_tools : List[str]
        List of tool names to execute.
    inner_jobs : int
        Number of parallel jobs for tool execution within this project.
    stop_on_error : bool
        If True, stop execution on first tool failure.
    progress_cb : callable, optional
        Progress callback function(event, tool, data). Default is None.
    start_root : str, optional
        Root path for relative path computation. Default is None.

    Returns
    -------
    Any
        Result from audit_file orchestrator function.

    Notes
    -----
    This is a wrapper around audit_file that provides a consistent interface
    for both sequential and parallel execution modes.
    """
    # audit_file is your tqdm-free worker that accepts progress_cb(event, tool, data)
    return audit_file(
        project, selected_tools, inner_jobs, stop_on_error, progress_cb=progress_cb, start_root=start_root
    )


def _interactive_tool_selection(available_tools: List[str]) -> List[str]:
    """Interactively select tools to run.
    
    Parameters
    ----------
    available_tools : List[str]
        List of all available tool names.
    
    Returns
    -------
    List[str]
        List of selected tool names.
    
    Notes
    -----
    Provides multiple selection methods:
    - Enter tool numbers (comma-separated): 1,3,5
    - Enter tool names (comma-separated): bandit,mypy
    - Enter 'all' to select all tools
    - Enter ranges: 1-3,5,7-9
    """
    typer.echo("\n" + "=" * 70)
    typer.echo("INTERACTIVE TOOL SELECTION")
    typer.echo("=" * 70)
    
    # Display available tools with numbers
    typer.echo("\nAvailable static analysis tools:")
    for idx, tool in enumerate(available_tools, 1):
        typer.echo(f"  {idx:2d}. {tool}")
    
    typer.echo("\n" + "-" * 70)
    typer.echo("Selection options:")
    typer.echo("  • Enter tool numbers (comma-separated): 1,3,5")
    typer.echo("  • Enter tool names (comma-separated): bandit,mypy,snyk")
    typer.echo("  • Enter ranges: 1-3,7 or 1-3,5,7-9")
    typer.echo("  • Enter 'all' to select all tools")
    typer.echo("  • Press Enter (empty) to select all tools")
    typer.echo("-" * 70)
    
    while True:
        selection = typer.prompt("\nSelect tools", default="all").strip().lower()
        
        # Handle empty or 'all'
        if not selection or selection == "all":
            typer.echo(f"✓ Selected all {len(available_tools)} tools")
            return available_tools
        
        # Try to parse the selection
        try:
            selected = _parse_tool_selection(selection, available_tools)
            if selected:
                typer.echo(f"\n✓ Selected {len(selected)} tool(s): {', '.join(selected)}")
                
                # Confirm selection
                if typer.confirm("Proceed with these tools?", default=True):
                    return selected
                else:
                    typer.echo("\nLet's try again...")
                    continue
            else:
                typer.echo("No valid tools selected. Please try again.", err=True)
        except ValueError as e:
            typer.echo(f"Error: {e}", err=True)
            typer.echo("Please try again with valid input.", err=True)


def _parse_tool_selection(selection: str, available_tools: List[str]) -> List[str]:
    """Parse tool selection string into list of tool names.
    
    Parameters
    ----------
    selection : str
        User input string (e.g., "1,3,5" or "bandit,mypy" or "1-3,5")
    available_tools : List[str]
        List of available tool names.
    
    Returns
    -------
    List[str]
        List of selected tool names.
    
    Raises
    ------
    ValueError
        If selection contains invalid numbers or tool names.
    """
    selected = set()
    parts = [p.strip() for p in selection.split(',')]
    
    for part in parts:
        if not part:
            continue
        
        # Check if it's a range (e.g., "1-3")
        if '-' in part:
            try:
                start, end = part.split('-', 1)
                start_idx = int(start.strip())
                end_idx = int(end.strip())
                
                if start_idx < 1 or end_idx > len(available_tools):
                    raise ValueError(f"Range {part} is out of bounds (1-{len(available_tools)})")
                
                if start_idx > end_idx:
                    raise ValueError(f"Invalid range {part}: start > end")
                
                for i in range(start_idx, end_idx + 1):
                    selected.add(available_tools[i - 1])
                
            except (ValueError, IndexError) as e:
                if "invalid literal" in str(e):
                    raise ValueError(f"Invalid range format: {part}")
                raise
        
        # Check if it's a number
        elif part.isdigit():
            idx = int(part)
            if idx < 1 or idx > len(available_tools):
                raise ValueError(f"Tool number {idx} is out of range (1-{len(available_tools)})")
            selected.add(available_tools[idx - 1])
        
        # Assume it's a tool name
        else:
            tool_name = part.lower()
            if tool_name in available_tools:
                selected.add(tool_name)
            else:
                # Fuzzy match attempt
                matches = [t for t in available_tools if tool_name in t or t in tool_name]
                if matches:
                    typer.echo(f"  Note: '{part}' matched to '{matches[0]}'")
                    selected.add(matches[0])
                else:
                    raise ValueError(f"Unknown tool: {part}")
    
    return sorted(list(selected))


@app.command("audit")
def audit(
    path: str,
    tools: Optional[List[str]] = typer.Option(
        None, "--tool", "-t", help="Tools to run (mutually exclusive with -i)"
    ),
    interactive: bool = typer.Option(
        False, "--interactive", "-i", help="Interactively select tools to run"
    ),
    jobs: int = typer.Option(4, "--jobs", "-j", min=2, help="Maximum parallel jobs"),
    stop_on_error: bool = typer.Option(
        False, "--stop-on-error", help="Stop on first tool failure"
    ),
    parallel: Parallel = typer.Option(
        Parallel.auto,
        "--parallel",
        "-p",
        help="Parallelization strategy: auto, thread, process, none",
    ),
    debug: bool = typer.Option(
        False, "--debug", help="Enable debug logging"
    ),
) -> None:
    """Run static analysis tools on a codebase.

    Discovers projects/files under the specified path and executes selected
    static analysis tools. Results are stored in the database for later export.

    Parameters
    ----------
    path : str
        Root path to analyze. Can be a file or directory.
    tools : List[str], optional
        List of tool names to run. If None, runs all available tools.
        Can be specified multiple times: --tool bandit --tool mypy
        Mutually exclusive with --interactive.
    interactive : bool, optional
        Enable interactive tool selection. If True, displays a menu to
        select tools before running. Default is False.
    jobs : int, optional
        Maximum number of parallel jobs. Default is 4.
    stop_on_error : bool, optional
        If True, stop execution on first tool failure. Default is False.
    parallel : Parallel, optional
        Parallelization strategy. Options: auto, thread, process, none.
        Default is auto (uses ThreadPoolExecutor).
    debug : bool, optional
        Enable debug logging. Default is False.

    Raises
    ------
    typer.BadParameter
        If unknown tools are specified or both --tool and --interactive are used.
    typer.Exit
        With code 1 if stop_on_error is True and a tool fails.

    Notes
    -----
    The database is automatically initialized if it doesn't exist.
    A unique run ID is generated for each audit session for log grouping.

    Progress is displayed using two progress bars:
    - Projects bar: tracks project discovery and completion
    - Tools bar: tracks individual tool executions

    When using parallel=process, progress callbacks cannot be passed due to
    pickling limitations, so progress is approximated.

    Examples
    --------
    Run all tools on current directory:
        $ python -m auditor audit .

    Run specific tools with parallelization:
        $ python -m auditor audit /path/to/code --tool bandit --tool mypy -j 8

    Interactive tool selection:
        $ python -m auditor audit /path/to/code --interactive
        $ python -m auditor audit /path/to/code -i

    Sequential execution (no parallelization):
        $ python -m auditor audit . --parallel none

    Stop on first error:
        $ python -m auditor audit . --stop-on-error
    """
    # Check for conflicting options
    if tools and interactive:
        typer.echo("Error: Cannot use both --tool and --interactive options", err=True)
        raise typer.Exit(code=1)
    
    if not check_database_ready(create=True):
        seed_db()
    # Single run id for nice grouped logs
    os.environ.setdefault("AUDIT_RUN_ID", datetime.now().strftime("%Y%m%d-%H%M%S"))

    available = available_tools()
    
    # Handle interactive tool selection
    if interactive:
        selected_tools = _interactive_tool_selection(available)
        if not selected_tools:
            typer.echo("No tools selected. Exiting.")
            raise typer.Exit(code=0)
    elif tools:
        selected_tools = [t.lower() for t in tools]
    else:
        # No tools specified, use all
        selected_tools = available
    
    print(f"Available tools: {', '.join(available)}")
    print(f"Selected tools: {', '.join(selected_tools)}")
    
    unknown = [t for t in selected_tools if t not in available_tools()]
    if unknown:
        raise typer.BadParameter(f"Unknown tools: {', '.join(unknown)}")

    target_path = Path(path).expanduser().resolve()
    print(f"Auditing path: {target_path}")

    projects = discover_files(target_path)
    print(f"Discovered {len(projects)} projects under {target_path}")
    if not projects:
        typer.echo("No projects discovered.")
        return

    # Avoid oversubscription: if we parallelize across projects, keep the inner job count small.
    inner_jobs = 1 if (parallel != Parallel.none and jobs > 1) else jobs

    print(f"Using parallelization: {parallel} with {jobs} jobs (inner jobs: {inner_jobs})")

    total_projects = len(projects)
    total_tools = len(projects) * len(selected_tools)

    # tqdm setup
    lock = Lock()
    bar_projects = tqdm(
        total=total_projects,
        desc="projects",
        unit="proj",
        dynamic_ncols=True,
        position=0,
    )
    bar_tools = tqdm(
        total=total_tools, desc="tools", unit="tool", dynamic_ncols=True, position=1
    )

    def make_progress_cb():
        # Only used in sequential or threaded project execution
        def _cb(event: str, tool: str, data: dict):
            # Count completion-like events for the tools bar
            if event in ("finished", "failed", "crashed", "parsing_failed"):
                with lock:
                    bar_tools.update(1)
                    # Optional: brief status in postfix
                    bar_tools.set_postfix_str(f"{event}:{tool}", refresh=True)

        return _cb

    try:
        # Sequential or single-project: simple loop with live per-tool updates
        if parallel == Parallel.none or jobs == 1 or len(projects) == 1:
            progress_cb = make_progress_cb()
            for project in projects:
                _run_one(
                    project,
                    selected_tools,
                    inner_jobs,
                    stop_on_error,
                    progress_cb=progress_cb,
                    start_root=str(project),
                )
                bar_projects.update(1)
            typer.secho("Done.", fg=typer.colors.GREEN)
            return

        # Parallel across projects
        first_error: Optional[BaseException] = None
        with _choose_executor(parallel, jobs) as ex:
            # For process mode, we cannot pass the callback (not picklable).
            pass_progress = parallel in (Parallel.thread, Parallel.auto)
            progress_cb = make_progress_cb() if pass_progress else None

            futures = {
                ex.submit(
                    _run_one, p, selected_tools, inner_jobs, stop_on_error, progress_cb, start_root=str(target_path)
                ): p
                for p in projects
            }

            try:
                for fut in as_completed(futures):
                    proj = futures[fut]
                    try:
                        fut.result()
                        # In process mode, approximate tools progress by full tool count per project
                        if not pass_progress:
                            with lock:
                                bar_tools.update(len(selected_tools))
                    except Exception as e:  # noqa: BLE001
                        from traceback import format_exc
                        print(format_exc())
                        print(f"[error] {proj}: {e}")
                        if not pass_progress:
                            # still count this project's tools (they finished/failed)
                            with lock:
                                bar_tools.update(len(selected_tools))
                        if stop_on_error and first_error is None:
                            first_error = e
                            # Best effort cancel of remaining work
                            for f in futures:
                                if not f.done():
                                    f.cancel()
                            break
                    finally:
                        bar_projects.update(1)

            except KeyboardInterrupt:
                for f in futures:
                    f.cancel()
                raise

        if first_error:
            raise typer.Exit(code=1)

        typer.secho("Done.", fg=typer.colors.GREEN)

    finally:
        # Make sure bars close cleanly even on exceptions
        try:
            bar_projects.close()
        finally:
            bar_tools.close()


__all__ = ["app"]
