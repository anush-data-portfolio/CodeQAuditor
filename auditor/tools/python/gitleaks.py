# auditor/tools/gitleaks.py
from __future__ import annotations

from typing import List

from..base import AuditTool, Finding, ToolRunResult


class GitleaksTool(AuditTool):
    """
    Secrets scanning with Gitleaks (workspace only, no git history by default).
    CLI JSON to stdout: `gitleaks detect --no-git --report-format=json --report-path=- --source .`
    """

    @property
    def name(self) -> str:
        return "gitleaks"

    def build_cmd(self, path: str) -> List[str]:
        return [
            "gitleaks",
            "detect",
            "--no-git",
            "--report-format=json",
            "--report-path=-",
            "--source",
            ".",
            "--no-banner",
            "--log-level=fatal",
        ]

    def parse(self, result: ToolRunResult) -> List[Finding]:
        data = result.parsed_json or []
        findings: List[Finding] = []
        if not isinstance(data, list):
            return findings
        for it in data:
            # Schema: {RuleID, Description, File, StartLine, EndLine, Secret, ...}
            findings.append(
                Finding(
                    tool=self.name,
                    rule_id=it.get("RuleID"),
                    severity="high",  # secrets default to high unless rule sets otherwise
                    message=it.get("Description") or "Secret detected",
                    file=it.get("File"),
                    line=it.get("StartLine"),
                    col=None,
                    end_line=it.get("EndLine"),
                    extra={
                        "match": it.get("Match"),
                        "entropy": it.get("Entropy"),
                        "tags": it.get("Tags"),
                        "rule_description": it.get("RuleDescription"),
                    },
                )
            )
        return findings
