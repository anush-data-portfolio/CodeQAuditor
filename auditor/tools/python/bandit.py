# auditor/tools/bandit.py
from __future__ import annotations

from typing import List

from ..base import AuditTool, Finding, ToolRunResult


class BanditTool(AuditTool):
    """
    Bandit security checks.
    CLI JSON: `bandit -r . -f json -q`
    """

    @property
    def name(self) -> str:
        return "bandit"

    def build_cmd(self, path: str) -> List[str]:
        return ["bandit", "-r", ".", "-f", "json", "-q"]

    def parse(self, result: ToolRunResult) -> List[Finding]:
        data = result.parsed_json or {}
        items = data.get("results", []) if isinstance(data, dict) else []
        findings: List[Finding] = []
        for it in items:
            line_range = it.get("line_range")
            last_line = line_range[-1] if line_range else None
            findings.append(
                Finding(
                    name=f"Bandit Security",
                    tool="bandit",
                    rule_id=it.get("test_id"),
                    message=it.get("issue_text", ""),
                    file=it.get("filename").replace("./", ""),
                    line=it.get("line_number"),
                    col=it.get("col_offset"),
                    end_line=last_line,
                    end_col=it.get("end_col_offset"),
                    extra={
                        "test_name": it.get("test_name"),
                        "confidence": (it.get("issue_confidence") or "").lower(),
                        "more_info": it.get("more_info"),
                    },
                    kind="issue",
                    category="security",
                )
            )
        return findings 
