# auditor/tools/semgrep.py
from __future__ import annotations

from pathlib import Path
from typing import List

from auditor.models import FINDING_KIND_ISSUE, Finding, ToolRunResult

from ..base import CommandAuditTool
from ..utils import load_json_payload, safe_relative_path


class SemgrepTool(CommandAuditTool):
    """
    Semgrep OSS scanning.
    Typical: `semgrep scan --config p/ci --json`
    """

    @property
    def name(self) -> str:
        return "semgrep"

    def __init__(self, config: str = "p/ci", **kw):
        super().__init__(**kw)
        self.config = config

    def build_cmd(self, path: str) -> List[str]:
        return ["semgrep", "scan", "--config", self.config, "--json"]

    def parse(self, result: ToolRunResult) -> List[Finding]:
        repo = Path(result.cwd).resolve()
        data = load_json_payload(result, default={})
        findings: List[Finding] = []
        results = data.get("results", []) if isinstance(data, dict) else []
        for r in results:
            extra = r.get("extra") or {}
            sev = (extra.get("severity") or "").lower() or None
            start = r.get("start") or {}
            end = r.get("end") or {}
            file_rel = safe_relative_path(r.get("path"), repo)
            findings.append(
                Finding(
                    name=f"semgrep.{r.get('check_id') or 'issue'}",
                    tool=self.name,
                    rule_id=r.get("check_id"),
                    message=extra.get("message") or "",
                    file=file_rel,
                    line=start.get("line"),
                    col=start.get("col"),
                    end_line=end.get("line"),
                    end_col=end.get("col"),
                    extra={
                        "metadata": extra.get("metadata"),
                        "fix": extra.get("fix"),
                        "severity": sev,
                    },
                    kind=FINDING_KIND_ISSUE,
                    category="security" if sev == "high" else "quality",
                    tags=[tag for tag in ["semgrep", sev, r.get("check_id")] if tag],
                    metrics={"count": 1.0},
                )
            )
        return findings
