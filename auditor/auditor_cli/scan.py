from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set

from auditor.models import Finding, RepoScanReport
from auditor.storage import AuditDatabase
from auditor.tools.base import AuditTool
from auditor.tools.python.bandit import BanditTool
from auditor.tools.python.jscpd import PythonJscpdTool
from auditor.tools.python.mypy import MypyTool
from auditor.tools.python.pyright import PyrightTool
from auditor.tools.python.radon import RadonTool
from auditor.tools.python.ruff import RuffTool
from auditor.tools.python.vulture import VultureTool
from auditor.tools.tsx import (
    BiomeTool,
    DepcheckTool,
    EslintTool,
    MadgeTool,
    TsPruneTool,
    TscTool,
    TsxJscpdTool,
)

PROJECT_MARKERS = {
    ".git",
    "pyproject.toml",
    "package.json",
    "requirements.txt",
    "setup.cfg",
    "setup.py",
    "Pipfile",
    "poetry.lock",
    "tsconfig.json",
}

EXCLUDED_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    "dist",
    "build",
    "out",
}


def ensure_node_prefix(node_prefix: Optional[str] = None) -> None:
    """
    Ensure AUDITOR_NODE_PREFIX is set so Node-based tools can locate
    their shared toolchain.
    """
    if node_prefix:
        os.environ["AUDITOR_NODE_PREFIX"] = str(Path(node_prefix).resolve())
    else:
        default_prefix = Path(__file__).resolve().parents[2]
        os.environ.setdefault("AUDITOR_NODE_PREFIX", str(default_prefix))


def build_default_tools() -> List[AuditTool]:
    """
    Instantiate the default suite of analyzers used by quick_probe and the CLI.
    """
    # remove out director if it exists
    return [
        BanditTool(timeout_s=180),
        PythonJscpdTool(min_tokens=50),
        MypyTool(timeout_s=300, ignore_missing_imports=True),
        PyrightTool(timeout_s=300),
        RadonTool(timeout_s=180),
        RuffTool(timeout_s=180),
        VultureTool(min_confidence=70),
        EslintTool(timeout_s=300),
        TscTool(timeout_s=300),
        MadgeTool(timeout_s=300),
        TsPruneTool(timeout_s=300),
        BiomeTool(timeout_s=300),
        DepcheckTool(timeout_s=300),
        TsxJscpdTool(min_tokens=50),
    ]


def is_project_dir(path: Path, include_all: bool = False) -> bool:
    if include_all:
        return True
    for marker in PROJECT_MARKERS:
        if (path / marker).exists():
            return True
    return False


def discover_projects(
    root: Path,
    *,
    include_root: bool = False,
    recursive: bool = False,
    include_hidden: bool = False,
    include_all: bool = False,
) -> List[Path]:
    """
    Discover repository candidates beneath `root`.
    """
    root = root.resolve()
    projects: List[Path] = []
    seen: Set[Path] = set()

    def consider(path: Path, force: bool = False) -> None:
        try:
            if not path.is_dir():
                return
        except FileNotFoundError:
            return
        resolved = path.resolve()
        if resolved in seen:
            return
        seen.add(resolved)
        if force or include_all or is_project_dir(resolved, include_all=include_all):
            projects.append(resolved)

    if include_root:
        consider(root, force=True)

    def iter_children(parent: Path) -> None:
        try:
            entries = sorted(parent.iterdir(), key=lambda p: p.name.lower())
        except FileNotFoundError:
            return
        for child in entries:
            if not child.is_dir():
                continue
            if not include_hidden and child.name.startswith("."):
                if child.name != ".git":
                    continue
            if child.name in EXCLUDED_DIR_NAMES:
                continue
            consider(child)
            if recursive:
                iter_children(child)

    if recursive:
        iter_children(root)
    else:
        try:
            for child in sorted(root.iterdir(), key=lambda p: p.name.lower()):
                if not child.is_dir():
                    continue
                if not include_hidden and child.name.startswith("."):
                    if child.name != ".git":
                        continue
                if child.name in EXCLUDED_DIR_NAMES:
                    continue
                consider(child)
        except FileNotFoundError:
            pass

    if not projects and root.is_dir() and not include_root:
        # Fallback: treat the root itself as a project when nothing else was detected
        consider(root, force=True)

    return projects


def scan_repository(
    repo_path: Path,
    db: AuditDatabase,
    tools: Sequence[AuditTool],
    *,
    store_logs: bool = True,
    collect_findings: bool = False,
    verbose: bool = True,
) -> RepoScanReport:
    repo_path = repo_path.resolve()
    findings_by_tool: Dict[str, List[Finding]] = {}

    if verbose:
        print(f"\n==> Scanning {repo_path}")

    for tool in tools:
        if verbose:
            print(f"[{repo_path.name}] Running {tool.name} …")

        scan_id = db.start_scan(tool.name, str(repo_path))
        run = tool.audit(str(repo_path))
        findings: List[Finding] = []
        if collect_findings:
            findings_by_tool[tool.name] = findings

        if findings:
            db.write_findings(scan_id, findings)
        else:
            db.write_findings(scan_id, [])
        run_dict = run.to_dict()
        db.finish_scan(
            scan_id,
            returncode=run_dict["returncode"],
            duration_s=run_dict["duration_s"],
            stdout_bytes=run_dict["stdout_bytes"],
            stderr_bytes=run_dict["stderr_bytes"],
            stdout_log=run_dict.get("stdout") if store_logs else None,
            stderr_log=run_dict.get("stderr") if store_logs else None,
        )

        if verbose:
            print(f"  {tool.name:<16} findings={len(findings):3d}")

    return RepoScanReport(
        repo=str(repo_path),
        findings_by_tool=findings_by_tool if collect_findings else None,
    )


def scan_workspace(
    workspace: Path,
    *,
    db_path: Path,
    tools: Optional[Sequence[AuditTool]] = None,
    node_prefix: Optional[str] = None,
    include_root: bool = False,
    recursive: bool = False,
    include_hidden: bool = False,
    include_all: bool = False,
    store_logs: bool = True,
    verbose: bool = True,
    collect_findings: bool = False,
) -> List[RepoScanReport]:
    ensure_node_prefix(node_prefix)

    workspace = workspace.resolve()
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    tool_instances = list(tools or build_default_tools())
    db = AuditDatabase(str(db_path))
    reports: List[RepoScanReport] = []

    try:
        projects = discover_projects(
            workspace,
            include_root=include_root,
            recursive=recursive,
            include_hidden=include_hidden,
            include_all=include_all,
        )
        if verbose:
            print(f"Discovered {len(projects)} project(s) under {workspace}")

        for project in projects:
            report = scan_repository(
                project,
                db,
                tool_instances,
                store_logs=store_logs,
                collect_findings=collect_findings,
                verbose=verbose,
            )
            reports.append(report)
    finally:
        db.close()

    return reports


def export_reports_to_json(
    reports: Iterable[RepoScanReport], output_path: Path
) -> None:
    payload = [report.to_dict() for report in reports]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


__all__ = [
    "build_default_tools",
    "discover_projects",
    "export_reports_to_json",
    "scan_repository",
    "scan_workspace",
]
