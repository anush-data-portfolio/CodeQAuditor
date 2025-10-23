from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Set

from auditor.models import ToolRunResult

from ..base import CommandAuditTool
from .nodejs import NodeToolMixin

DEFAULT_ESLINT_SUPPRESS: Set[str] = {
    "import/no-unresolved",
    "node/no-missing-import",
    "node/no-missing-require",
    "n/no-missing-import",
    "n/no-missing-require",
}


class EslintTool(CommandAuditTool, NodeToolMixin):
    """
    Minimal ESLint wrapper that returns the raw ToolRunResult.
    """

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
        self.exts = exts or [".ts", ".tsx", ".js", ".jsx"]
        self.config_path = config_path
        self.max_warnings = max_warnings
        self.extra_args = extra_args or []
        self.suppress_unresolved_imports = suppress_unresolved_imports
        self.suppress_rules = set(suppress_rules or DEFAULT_ESLINT_SUPPRESS)
        self.package_version = package_version

    def build_cmd(self, path: str) -> List[str]:
        cwd = Path(path).resolve()
        patterns: List[str] = []
        for ext in self.exts:
            suffix = ext if ext.startswith(".") else f".{ext}"
            patterns.append(f"**/*{suffix}")

        cmd = self._node_cmd(
            cwd=cwd,
            exe="eslint",
            npm_package="eslint",
            version=self.package_version,
            subcommand=[],
            extra=["-f", "json", "--no-error-on-unmatched-pattern", *patterns],
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
        return cmd

    def parse(self, result: ToolRunResult) -> None:
        """Placeholder hook for future schema integration."""
        return None


__all__ = ["EslintTool"]
