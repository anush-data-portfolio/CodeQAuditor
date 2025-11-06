"""ESLint linter tool implementation.

This module implements the ESLint tool wrapper for linting JavaScript
and TypeScript code.

Classes
-------
EslintTool : ESLint tool implementation

Examples
--------
>>> tool = EslintTool()
>>> result = tool.audit("app.js")

See Also
--------
auditor.infra.tools.base : Base tool class
auditor.core.models.parsers.eslint : Result parser
"""
from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from auditor.core.models import ToolRunResult

from ..base import CommandAuditTool, NodeToolMixin

DEFAULT_EXTS = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]
DEFAULT_SUPPRESS = {
    "import/no-unresolved",
    "node/no-missing-import",
    "node/no-missing-require",
    "n/no-missing-import",
    "n/no-missing-require",
}


class EslintTool(CommandAuditTool, NodeToolMixin):
    """Lightweight ESLint runner that returns the raw ToolRunResult."""

    @property
    def name(self) -> str:
        return "eslint"

    def __init__(
        self,
        exts: Optional[List[str]] = None,
        config_path: Optional[str] = None,
        max_warnings: Optional[int] = None,
        extra_args: Optional[List[str]] = None,
        suppress_unresolved_imports: bool = True,
        suppress_rules: Optional[List[str]] = None,
        package_version: Optional[str] = None,
        **kw,
    ) -> None:
        super().__init__(**kw)
        self.exts = exts or list(DEFAULT_EXTS)
        self.config_path = Path(config_path).resolve() if config_path else None
        self.max_warnings = max_warnings
        self.extra_args = extra_args or []
        self.suppress_unresolved_imports = suppress_unresolved_imports
        self.suppress_rules = set(suppress_rules or DEFAULT_SUPPRESS)
        self.package_version = package_version

    def build_cmd(self, path: str, cwd: Optional[Path] = None) -> List[str]:
        self._prepare_node_env()


        extra_args: List[str] = [
            "-f",
            "json",
            "--no-error-on-unmatched-pattern",
            "--no-inline-config",
            "--no-warn-ignored",
        ]

        cmd = self._node_cmd(
            exe="eslint",
            cwd=cwd,
            npm_package="eslint",
            version=self.package_version,
            subcommand=[],
            extra=extra_args,
        )

        if self.exts:
            cmd += ["--ext", ",".join(self.exts)]

        if self.config_path:
            cmd += ["-c", str(self.config_path)]
        else:
            central = self._node_prefix() / "eslint.config.mjs"
            if central.exists():
                cmd += ["-c", str(central)]

        if self.max_warnings is not None:
            cmd += ["--max-warnings", str(self.max_warnings)]

        if self.suppress_unresolved_imports:
            for rule in sorted(self.suppress_rules):
                cmd += ["--rule", f"{rule}:off"]

        cmd += self.extra_args

        cmd += [path]
        return cmd

    def audit(self, path: str | Path) -> ToolRunResult:
        # if its a non ts,tsx,javascript file, skip eslint
        path_str = str(path)
        if not any(path_str.endswith(ext) for ext in self.exts):
            return ToolRunResult(
                tool=self.name,
                success=True,
                parsed_json=[],
                raw_output="",
                cmd=[str(path)],
            )
        return super().audit(path)

    def parse(self, result: ToolRunResult) -> None:
        return None


__all__ = ["EslintTool"]
