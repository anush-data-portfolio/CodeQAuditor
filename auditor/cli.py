from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

import typer

from auditor.db.seed import describe_database, seed_database
from auditor.models.orm import Base
from auditor.services.orchestrator import (
    available_tools,
    discover_projects,
    run_project,
    run_tool_direct,
)


app = typer.Typer(help="Auditor CLI")


@app.command("seed-db")
def seed_db() -> None:
    seed_database(Base)
    typer.echo(f"Database ready at {describe_database()}")


@app.command("run-tool")
def run_tool(
    tool: str,
    target: str,
    json_out: Optional[str] = typer.Option(
        None, "--json-out", help="Write JSON payload to this path"
    ),
) -> None:
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


@app.command("audit")
def audit(
    path: str,
    tools: Optional[List[str]] = typer.Option(
        None, "--tool", "-t", help="Tools to run"
    ),
    jobs: int = typer.Option(4, "--jobs", "-j", min=1, help="Maximum parallel jobs"),
    multi: bool = typer.Option(False, "--multi", help="Treat path as workspace"),
    stop_on_error: bool = typer.Option(
        False, "--stop-on-error", help="Stop on first tool failure"
    ),
) -> None:

    available = available_tools()
    print(f"Available tools: {', '.join(available)}")
    selected_tools = [t.lower() for t in (tools or available)] if tools else available
    unknown = [t for t in selected_tools if t not in available_tools()]
    if unknown:
        raise typer.BadParameter(f"Unknown tools: {', '.join(unknown)}")

    target_path = Path(path).expanduser().resolve()

    projects = [target_path]
    if multi:
        projects = discover_projects(target_path)
        print(projects)
        if not projects:
            typer.echo("No projects discovered.")
            return

    for project in projects:
        run_project(project, selected_tools, jobs, stop_on_error)

    typer.secho("Done.", fg=typer.colors.GREEN)


__all__ = ["app"]
