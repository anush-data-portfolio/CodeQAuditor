# auditor/tools/semgrep.py
"""Semgrep pattern matching tool implementation.

This module implements the Semgrep tool wrapper for pattern-based
static analysis.

Classes
-------
SemgrepTool : Semgrep tool implementation

Examples
--------
>>> tool = SemgrepTool()
>>> result = tool.audit("/path/to/project")

See Also
--------
auditor.infra.tools.base : Base tool class
auditor.core.models.parsers.semgrep : Result parser
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Sequence, Union

from auditor.core.models import ToolRunResult  # <- match your base import
from ..base import CommandAuditTool


DEFAULT_CONFIGS: tuple[str, ...] = (
    # Broad, build-free, cross-language packs; tweak as you like:
    "p/react",
    "p/typescript",
    "p/javascript",
    "p/python",
    "p/owasp-top-ten",
    "p/secrets",
)

DEFAULT_EXCLUDES: tuple[str, ...] = (
    "node_modules", ".next", "dist", "build", "coverage",
    ".git", ".cache", ".turbo", ".venv", "__pycache__",
)

_SEV_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]  # semgrep severities


class SemgrepTool(CommandAuditTool):
    """
    Semgrep scanner (no-build). Pulls rules from the registry by default and
    emits normalized findings for easy DB ingestion.
    """

    @property
    def name(self) -> str:
        return "semgrep"

    def __init__(
        self,
        *,
        configs: Optional[Sequence[str]] = None,
        excludes: Optional[Sequence[str]] = None,
        jobs: Optional[int] = None,             # concurrency
        rule_timeout_s: int = 30,               # per-rule timeout
        target: Optional[Union[str, Path]] = None,
        extra_args: Optional[Sequence[str]] = None,
        **kw,
    ) -> None:
        super().__init__(**kw)

        self.configs = list(configs) if configs else list(DEFAULT_CONFIGS)
        self.excludes = list(excludes) if excludes else list(DEFAULT_EXCLUDES)
        self.jobs = jobs or (self.cpus or None)
        self.rule_timeout_s = rule_timeout_s
        self.target = str(target) if target else None
        self.extra_args = list(extra_args or [])

        # Quiet + privacy by default
        self.env.setdefault("SEMGREP_SEND_METRICS", "0")
        self.env.setdefault("SEMGREP_ENABLE_VERSION_CHECK", "0")

    # ----- runner ---------------------------------------------------------------

    def build_cmd(self, path: str) -> List[str]:
        # Prefer the path passed by the orchestrator; fall back to explicit target
        target = self.target or path

        cmd: List[str] = [
            "semgrep", "scan",
            "--json",
            "--metrics", "off",
            "--timeout", str(self.rule_timeout_s),
            "--error",  # nonzero exit for real errors, not findings
        ]

        # Concurrency if provided
        if self.jobs:
            cmd += ["--jobs", str(self.jobs)]

        # Exclude vendor/build dirs (repeatable flag)
        for ex in self.excludes:
            cmd += ["--exclude", ex]

        # Registry configs (repeatable flag)
        for cfg in self.configs:
            cmd += ["--config", cfg]

        # Any caller-provided extras last
        if self.extra_args:
            cmd += list(self.extra_args)

        cmd += [target]
        return cmd

    # ----- parsing --------------------------------------------------------------

    # def parse(self, result: ToolRunResult) -> Dict:
    #     """
    #     Normalize Semgrep JSON into:
    #       {
    #         "summary": {...},
    #         "findings": [
    #           {
    #             "rule_id": str, "severity": str, "message": str,
    #             "path": str, "start_line": int, "end_line": int,
    #             "start_col": int|None, "end_col": int|None,
    #             "metadata": dict, "fix": dict|None
    #           }, ...
    #         ]
    #       }
    #     """
    #     raw = result.parsed_json
    #     if not isinstance(raw, dict):
    #         result.parsed_json = {"summary": {}, "findings": []}
    #         return result.parsed_json

    #     results = raw.get("results", []) or []
    #     findings: List[Dict] = []

    #     by_sev: Dict[str, int] = {}
    #     by_rule: Dict[str, int] = {}
    #     by_file: Dict[str, int] = {}

    #     for r in results:
    #         extra = r.get("extra", {}) or {}
    #         sev = (extra.get("severity") or "INFO").upper()
    #         rule_id = extra.get("check_id") or r.get("check_id") or "unknown"
    #         msg = extra.get("message") or ""
    #         meta = extra.get("metadata") or {}
    #         fix = extra.get("fix")  # rare

    #         path = r.get("path") or ""
    #         start = r.get("start", {}) or {}
    #         end = r.get("end", {}) or {}

    #         item = {
    #             "rule_id": rule_id,
    #             "severity": sev,
    #             "message": msg,
    #             "path": path,
    #             "start_line": int(start.get("line", 0) or 0),
    #             "end_line": int(end.get("line", 0) or 0),
    #             "start_col": int(start.get("col", 0) or 0) or None,
    #             "end_col": int(end.get("col", 0) or 0) or None,
    #             "metadata": meta,
    #             "fix": fix if isinstance(fix, dict) else None,
    #         }
    #         findings.append(item)

    #         by_sev[sev] = by_sev.get(sev, 0) + 1
    #         by_rule[rule_id] = by_rule.get(rule_id, 0) + 1
    #         by_file[path] = by_file.get(path, 0) + 1

    #     # Ordered severity summary
    #     sev_summary = {k: by_sev.get(k, 0) for k in _SEV_ORDER if k in by_sev}

    #     normalized = {
    #         "summary": {
    #             "total": len(findings),
    #             "by_severity": sev_summary,
    #             "by_rule": sorted(by_rule.items(), key=lambda kv: kv[1], reverse=True),
    #             "by_file_top10": sorted(by_file.items(), key=lambda kv: kv[1], reverse=True)[:10],
    #             "duration_s": result.duration_s,
    #             "returncode": result.returncode,
    #         },
    #         "findings": findings,
    #     }
    #     result.parsed_json = normalized
    #     return normalized
