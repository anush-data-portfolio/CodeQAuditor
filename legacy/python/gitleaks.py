# auditor/tools/gitleaks.py
from __future__ import annotations

from pathlib import Path
from typing import List

from auditor.models import FINDING_KIND_ISSUE, Finding, ToolRunResult

from ..base import CommandAuditTool
from ..utils import load_json_payload, safe_relative_path


class GitleaksTool(CommandAuditTool):
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
        repo = Path(result.cwd).resolve()
        data = load_json_payload(result, default=[])
        findings: List[Finding] = []
        if not isinstance(data, list):
            return findings
        for it in data:
            file_rel = safe_relative_path(it.get("File"), repo)
            severity = (it.get("RuleID") or "").split("_")[0].lower() if it.get("RuleID") else "info"
            tags = ["gitleaks", severity, it.get("RuleID"), it.get("RuleDescription")]
            tags = [tag for tag in tags if tag]
            findings.append(
                Finding(
                    name=f"gitleaks.{it.get('RuleID') or 'secret'}",
                    tool=self.name,
                    rule_id=it.get("RuleID"),
                    message=it.get("Description") or "Secret detected",
                    file=file_rel,
                    line=it.get("StartLine"),
                    col=None,
                    end_line=it.get("EndLine"),
                    extra={
                        "match": it.get("Match"),
                        "entropy": it.get("Entropy"),
                        "tags": it.get("Tags"),
                        "rule_description": it.get("RuleDescription"),
                        "commit": it.get("Commit"),
                    },
                    kind=FINDING_KIND_ISSUE,
                    category="security",
                    tags=tags,
                    metrics={
                        "count": 1.0,
                        "severity_weight": _severity_weight(severity),
                    },
                )
            )
        return findings


def _severity_weight(severity: str) -> float:
    severity = severity.lower()
    if severity in {"critical", "high"}:
        return 1.0
    if severity == "medium":
        return 0.6
    if severity == "low":
        return 0.3
    return 0.1
