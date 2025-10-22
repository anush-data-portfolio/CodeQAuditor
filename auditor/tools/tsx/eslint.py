# auditor/tools/eslint.py
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..base import AuditTool, Finding, ToolRunResult
from .nodejs import NodeToolMixin

DEFAULT_ESLINT_SUPPRESS = {
    "import/no-unresolved",
    "node/no-missing-import",
    "node/no-missing-require",
    "n/no-missing-import",
    "n/no-missing-require",
}

class EslintTool(AuditTool, NodeToolMixin):
    """
    ESLint wrapper for JS/TS/TSX with JSON output.
    Focus on quality/formatting; suppress unresolved-import noise.
    """

    @property
    def name(self) -> str:
        return "eslint"

    def __init__(
        self,
        exts: Optional[List[str]] = None,         # [".ts",".tsx",".js",".jsx"]
        config_path: Optional[str] = None,        # use project config if present
        max_warnings: Optional[int] = None,
        extra_args: Optional[List[str]] = None,
        suppress_unresolved_imports: bool = True,
        suppress_rules: Optional[List[str]] = None,
        package_version: Optional[str] = None,    # e.g., "^9"
        **kw: Any,
    ) -> None:
        super().__init__(**kw)
        self.exts = exts or [".ts", ".tsx", ".js", ".jsx"]
        self.config_path = config_path
        self.max_warnings = max_warnings
        self.extra_args = extra_args or []
        self.suppress_unresolved_imports = suppress_unresolved_imports
        self.suppress_rules = set(suppress_rules or DEFAULT_ESLINT_SUPPRESS)
        self.package_version = package_version

    def build_cmd(self, path: str) -> List[str]:
        cwd = Path(path).resolve()

        # Build explicit file patterns so ESLint never says "all files ignored".
        # Use patterns relative to the target repo's cwd.
        patterns = []
        exts = self.exts or [".ts", ".tsx", ".js", ".jsx"]
        for e in exts:
            e = e if e.startswith(".") else f".{e}"
            patterns.append(f"**/*{e}")

        cmd = self._node_cmd(
            cwd=cwd,
            exe="eslint",
            npm_package="eslint",
            version=self.package_version,
            subcommand=[],
            extra=["-f", "json", "--no-error-on-unmatched-pattern", *patterns],
        )

        # No need for --ext when we already pass explicit patterns,
        # but keeping it is harmless. Comment out if you prefer.
        if self.exts:
            cmd += ["--ext", ",".join(self.exts)]

        # Choose config: explicit → central → ESLint discovery
        cfg_path: Optional[Path] = None
        if self.config_path:
            cfg_path = Path(self.config_path)
        else:
            central = self._node_prefix() / "eslint.config.mjs"
            if central.exists():
                cfg_path = central
        if cfg_path:
            cmd += ["-c", str(cfg_path)]

        if self.max_warnings is not None:
            cmd += ["--max-warnings", str(self.max_warnings)]

        if self.suppress_unresolved_imports:
            for r in sorted(self.suppress_rules):
                cmd += ["--rule", f"{r}:off"]

        # If you want to *force* ignoring inline eslint-disable in repos via CLI
        # instead of config, uncomment this:
        # cmd += ["--no-inline-config"]

        cmd += self.extra_args
        return cmd


    def parse(self, result: ToolRunResult) -> List[Finding]:
        root = Path(result.cwd).resolve()
        findings: List[Finding] = []

        # ESLint prints a JSON array
        try:
            data = result.parsed_json if isinstance(result.parsed_json, list) else json.loads(result.stdout or "[]")
        except Exception:
            data = []

        total_errors = 0
        total_warnings = 0

        for file_obj in data:
            file_path = file_obj.get("filePath")
            rel = None
            if file_path:
                try:
                    rel = str(Path(file_path).resolve().relative_to(root))
                except Exception:
                    rel = file_path

            total_errors += int(file_obj.get("errorCount", 0) or 0)
            total_warnings += int(file_obj.get("warningCount", 0) or 0)

            for m in file_obj.get("messages", []) or []:
                rule = m.get("ruleId")
                if rule and rule in self.suppress_rules:
                    continue  # drop unresolved import noise

                line = m.get("line"); col = m.get("column")
                end_line = m.get("endLine"); end_col = m.get("endColumn")

                # quick categorization
                cat = "lint"
                if rule:
                    if rule.startswith("@typescript-eslint"):
                        cat = "types"
                    elif rule.startswith("jsx-a11y"):
                        cat = "a11y"

                tags = ["eslint"]
                if rule:
                    tags.append(rule)
                    if "/" in rule:
                        tags.append(rule.split("/")[0])

                findings.append(
                    Finding(
                        name=f"eslint.{rule}" if rule else "eslint.diagnostic",
                        tool=self.name,
                        rule_id=rule,
                        message=m.get("message", ""),
                        file=rel,
                        line=line,
                        col=col,
                        end_line=end_line,
                        end_col=end_col,
                        fingerprint=None,
                        extra={
                            "nodeType": m.get("nodeType"),
                            "suggestions": m.get("suggestions"),
                            "fix": m.get("fix"),
                            "raw": m,
                        },
                        kind="issue",
                        category=cat,
                        tags=tags,
                        metrics={"count": 1.0},
                    )
                )

        return findings
