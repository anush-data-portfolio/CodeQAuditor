# auditor/tools/depcheck.py
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..base import AuditTool, Finding, ToolRunResult
from .nodejs import NodeToolMixin

class DepcheckTool(AuditTool, NodeToolMixin):
    """
    Depcheck: static analysis of package.json usage.
    We report only UNUSED dependencies/devDependencies; we IGNORE "missing"
    because you're intentionally not installing runtime deps.
    """

    @property
    def name(self) -> str:
        return "depcheck"

    def __init__(
        self,
        ignore_missing: bool = True,
        extra_args: Optional[List[str]] = None,
        package_version: Optional[str] = None,  # e.g., "^1"
        **kw,
    ):
        super().__init__(**kw)
        self.ignore_missing = ignore_missing
        self.extra_args = extra_args or []
        self.package_version = package_version

    def build_cmd(self, path: str) -> List[str]:
        cwd = Path(path).resolve()
        cmd = self._node_cmd(
            cwd=cwd,
            exe="depcheck",
            npm_package="depcheck",
            version=self.package_version,
            extra=["--json", "."],
        )
        cmd += self.extra_args
        return cmd

    def parse(self, result: ToolRunResult) -> List[Finding]:
        findings: List[Finding] = []
        try:
            data = result.parsed_json if isinstance(result.parsed_json, dict) else json.loads(result.stdout or "{}")
        except Exception:
            data = {}

        unused_deps = list(data.get("dependencies") or [])
        unused_dev = list(data.get("devDependencies") or [])
        missing = data.get("missing") or {}  # intentionally ignored (noise)

        for pkg in unused_deps:
            findings.append(
                Finding(
                    name="depcheck.unused-dependency",
                    tool=self.name,
                    rule_id="unused-dependency",
                    message=f"Unused dependency: {pkg}",
                    file="package.json",
                    line=None,
                    col=None,
                    extra={"package": pkg},
                    kind="analysis",
                    category="dependency",
                    tags=["depcheck", "unused", "dependency"],
                    metrics={"count": 1.0},
                )
            )

        for pkg in unused_dev:
            findings.append(
                Finding(
                    name="depcheck.unused-dev-dependency",
                    tool=self.name,
                    rule_id="unused-dev-dependency",
                    message=f"Unused devDependency: {pkg}",
                    file="package.json",
                    line=None,
                    col=None,
                    extra={"package": pkg},
                    kind="analysis",
                    category="dependency",
                    tags=["depcheck", "unused", "devDependency"],
                    metrics={"count": 1.0},
                )
            )

        return findings
