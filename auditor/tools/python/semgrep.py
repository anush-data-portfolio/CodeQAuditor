# auditor/tools/semgrep.py
from __future__ import annotations

from typing import List

from..base import AuditTool, Finding, ToolRunResult


class SemgrepTool(AuditTool):
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
        data = result.parsed_json or {}
        findings: List[Finding] = []
        results = data.get("results", []) if isinstance(data, dict) else []
        for r in results:
            extra = r.get("extra") or {}
            sev = (extra.get("severity") or "").lower() or None
            start = r.get("start") or {}
            end = r.get("end") or {}
            findings.append(
                Finding(
                    tool=self.name,
                    rule_id=r.get("check_id"),
                    severity=sev,
                    message=extra.get("message") or "",
                    file=r.get("path"),
                    line=start.get("line"),
                    col=start.get("col"),
                    end_line=end.get("line"),
                    end_col=end.get("col"),
                    extra={"metadata": extra.get("metadata"), "fix": extra.get("fix")},
                )
            )
        return findings
