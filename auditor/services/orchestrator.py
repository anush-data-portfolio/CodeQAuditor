from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

from auditor.models.orm import Base
from auditor.models.schema import (
    ToolRunResult,
    bandit_json_to_models,
    eslint_rows_to_models,
    mypy_ndjson_to_models,
    radon_to_models,
    vulture_text_to_models,
)
from auditor.tools.bandit.base import BanditTool
from auditor.tools.mypy.base import MypyTool
from auditor.tools.radon.base import RadonTool
from auditor.tools.vulture.base import VultureTool
from auditor.tools.eslint.base import EslintTool

from auditor.db.utils import save_scan_and_rows


TOOL_FACTORIES = {
    "bandit": BanditTool,
    "mypy": MypyTool,
    "radon": RadonTool,
    "vulture": VultureTool,
    "eslint": EslintTool,
}


def available_tools() -> List[str]:
    return list(TOOL_FACTORIES.keys())


def instantiate_tool(name: str):
    try:
        factory = TOOL_FACTORIES[name.lower()]
    except KeyError as exc:  # pragma: no cover - defensive
        raise ValueError(f"Unknown tool '{name}'") from exc
    return factory()


def run_tool_direct(name: str, target: str) -> ToolRunResult:
    tool = instantiate_tool(name)
    run = tool.audit(target)
    if isinstance(run, ToolRunResult):
        return run
    # Some tools may return tuple/findings; standardise by reading second value
    if isinstance(run, tuple):
        _, result = run
        return result
    raise TypeError(f"Tool {name} returned unexpected payload: {type(run)!r}")


def parse_to_models(
    result: ToolRunResult, *, radon_bundle: Mapping[str, object] | None = None
):
    tool = result.tool.lower()
    if tool == "bandit":
        payload = {}
        if isinstance(result.parsed_json, dict):
            payload = result.parsed_json
        scan, rows = bandit_json_to_models(payload.get("results", []), cwd=result.cwd)
    elif tool == "mypy":
        text = (result.stdout or "").strip()
        scan, rows = mypy_ndjson_to_models(text, cwd=result.cwd)
    elif tool == "radon":
        payload = result.parsed_json or {}
        scan, rows = radon_to_models(payload, cwd=result.cwd)
    elif tool == "vulture":
        scan, rows = vulture_text_to_models(
            result.stdout or "", cwd=result.cwd, min_confidence=50
        )
    elif tool == "eslint":
        shim = SimpleNamespace(
            parsed_json=result.parsed_json,
            stdout=result.stdout,
            stderr=result.stderr,
            cwd=result.cwd,
            exitcode=result.returncode,
            duration_s=result.duration_s,
            cmd=result.cmd,
        )
        scan, rows = eslint_rows_to_models(shim, radon_bundle=radon_bundle)
    else:  # pragma: no cover - defensive
        raise ValueError(f"Unsupported tool '{result.tool}'")
    return scan, rows


def parsetomodels(result: ToolRunResult, **kwargs):
    return parse_to_models(result, **kwargs)


@dataclass
class ToolJob:
    name: str
    target: Path
    output: Path


def _invoke_run_tool(job: ToolJob) -> Tuple[str, int, str, str, Path]:
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
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return job.name, proc.returncode, proc.stdout, proc.stderr, job.output


def _load_run_result(path: Path) -> ToolRunResult:
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


def run_project(
    project_path: Path,
    tools: Sequence[str],
    jobs: int,
    stop_on_error: bool,
) -> None:
    project_str = str(project_path)
    print(f"\n=== Auditing {project_str}")

    with tempfile.TemporaryDirectory(prefix="auditor-") as tmpdir:
        tmpdir_path = Path(tmpdir)
        jobs_to_run = [
            ToolJob(name=tool, target=project_path, output=tmpdir_path / f"{tool}.json")
            for tool in tools
        ]

        max_workers = max(1, min(jobs, len(jobs_to_run)))
        results: Dict[str, ToolRunResult] = {}
        errors: Dict[str, Tuple[int, str]] = {}

        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            future_map = {
                executor.submit(_invoke_run_tool, job): job for job in jobs_to_run
            }
            for future in as_completed(future_map):
                job = future_map[future]
                tool, returncode, stdout, stderr, output_path = future.result()
                if returncode != 0:
                    message = stderr.strip() or stdout.strip() or "unknown error"
                    errors[tool] = (returncode, message)
                    if stop_on_error:
                        raise RuntimeError(
                            f"{tool} failed (exit {returncode}): {message}"
                        )
                    print(f"[WARN] {tool} failed (exit {returncode}): {message}")
                    continue
                try:
                    results[tool] = _load_run_result(output_path)
                except Exception as exc:  # pragma: no cover
                    errors[tool] = (returncode, str(exc))
                    if stop_on_error:
                        raise
                    print(f"[WARN] Unable to parse {tool} output: {exc}")

        radon_bundle: Mapping[str, Any] | None = None
        radon_result = results.get("radon")
        if radon_result and isinstance(radon_result.parsed_json, Mapping):
            radon_bundle = radon_result.parsed_json

        for tool in tools:
            if tool not in results:
                continue
            run_result = results[tool]
            if tool == "eslint":
                scan, rows = parse_to_models(run_result, radon_bundle=radon_bundle)
            else:
                scan, rows = parse_to_models(run_result)
            _, count = save_scan_and_rows(Base, scan, rows)
            print(f"[OK] {tool} wrote 1 scan row, {count} result rows")

        if errors and not stop_on_error:
            print(
                "[INFO] Completed with errors: "
                + ", ".join(f"{k}(exit {v[0]})" for k, v in errors.items())
            )


EXCLUDED_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    ".mypy_cache",
}


def discover_projects(root: Path) -> List[Path]:
    projects: List[Path] = []
    for child in sorted(root.iterdir(), key=lambda p: p.name.lower()):
        if not child.is_dir():
            continue
        if child.name in EXCLUDED_DIRS:
            continue
        projects.append(child)
    return projects


__all__ = [
    "available_tools",
    "instantiate_tool",
    "run_tool_direct",
    "run_project",
    "discover_projects",
    "parse_to_models",
    "parsetomodels",
]
