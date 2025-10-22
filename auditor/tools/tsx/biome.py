# auditor/tools/biome.py
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..base import AuditTool, Finding, ToolRunResult
from .nodejs import NodeToolMixin

class BiomeTool(AuditTool, NodeToolMixin):
    """
    Biome (successor to Rome): fast lint/format checks.
    Great fallback when ESLint config is missing; runs via npx if needed.
    """

    @property
    def name(self) -> str:
        return "biome"

    def __init__(
        self,
        paths: Optional[List[str]] = None,       # default: "."
        report_unformatted: bool = True,        # include format diagnostics
        extra_args: Optional[List[str]] = None,
        package_version: Optional[str] = None,  # e.g., "^1.8"
        **kw,
    ):
        super().__init__(**kw)
        self.paths = paths or ["."]
        self.report_unformatted = report_unformatted
        self.extra_args = extra_args or []
        self.package_version = package_version

    def build_cmd(self, path: str) -> List[str]:
        cwd = Path(path).resolve()
        cmd = self._node_cmd(
            cwd=cwd,
            exe="biome",
            npm_package="@biomejs/biome",
            version=self.package_version,
            subcommand=["check"],
            extra=["--reporter", "json", *self.paths],
        )
        if not self.report_unformatted:
            cmd += ["--no-errors-on-unformatted"]
        cmd += self.extra_args
        return cmd

    def parse(self, result: ToolRunResult) -> List[Finding]:
        findings: List[Finding] = []
        try:
            data = result.parsed_json if isinstance(result.parsed_json, dict) else json.loads(result.stdout or "{}")
        except Exception:
            data = {}

        files = data.get("files") or []
        total = 0
        errors = 0
        warnings = 0

        for f in files:
            rel = f.get("path")
            for d in f.get("diagnostics") or []:
                total += 1
                sev = (d.get("severity") or "").lower()
                if sev == "error":
                    errors += 1
                elif sev == "warning":
                    warnings += 1

                code = d.get("category") or d.get("code")
                msg = d.get("message") or d.get("title") or "biome diagnostic"

                span = ((d.get("location") or {}).get("span") or {})
                start = (span.get("start") or {})
                end = (span.get("end") or {})
                s_line = (start.get("line") or 0) + 1 if isinstance(start.get("line"), int) else None
                s_col = (start.get("column") or 0) + 1 if isinstance(start.get("column"), int) else None
                e_line = (end.get("line") or 0) + 1 if isinstance(end.get("line"), int) else None
                e_col = (end.get("column") or 0) + 1 if isinstance(end.get("column"), int) else None

                cat = "lint"
                if d.get("category") == "format":
                    cat = "format"

                findings.append(
                    Finding(
                        name=f"biome.{code}" if code else "biome.diagnostic",
                        tool=self.name,
                        rule_id=str(code) if code else None,
                        message=msg,
                        file=rel,
                        line=s_line,
                        col=s_col,
                        end_line=e_line,
                        end_col=e_col,
                        extra={"severity": sev, "raw": d},
                        kind="issue",
                        category=cat,
                        tags=["biome"] + ([str(code)] if code else []),
                        metrics={"count": 1.0},
                    )
                )

        return findings
