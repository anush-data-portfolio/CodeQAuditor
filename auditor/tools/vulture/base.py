from __future__ import annotations

from pathlib import Path
from typing import Any, List, Optional, Union

from auditor.models import ToolRunResult

from ..base import AuditTool


class VultureTool(AuditTool):
    """
    Thin wrapper around `vulture` that returns the raw ToolRunResult.
    """

    @property
    def name(self) -> str:
        return "vulture"

    def __init__(
        self,
        *,
        min_confidence: int = 70,
        ignore_decorators: Optional[List[str]] = None,
        ignore_names: Optional[List[str]] = None,
        exclude_globs: Optional[List[str]] = None,
        extra_args: Optional[List[str]] = None,
        **kw: Any,
    ) -> None:
        super().__init__(**kw)
        self.min_confidence = int(min_confidence)
        self.ignore_decorators = ignore_decorators or []
        self.ignore_names = ignore_names or []
        self.exclude_globs = exclude_globs or [
            "*/.venv/*",
            "*/venv/*",
            "*/.auditenv/*",
            "*/.git/*",
            "*/.hg/*",
            "*/.svn/*",
            "*/.tox/*",
            "*/.mypy_cache/*",
            "*/__pycache__/*",
            "*/node_modules/*",
            "*/build/*",
            "*/dist/*",
        ]
        self.extra_args = extra_args or []

    def build_cmd(self, path: str) -> List[str]:
        return ["vulture", path]

    def audit(self, path: Union[str, Path]) -> ToolRunResult:
        cwd_str = path if isinstance(path, str) else str(Path(path))

        cmd: List[str] = ["vulture"]
        if self.exclude_globs:
            cmd += ["--exclude", ",".join(self.exclude_globs)]
        if self.ignore_decorators:
            cmd += ["--ignore-decorators", ",".join(self.ignore_decorators)]
        if self.ignore_names:
            cmd += ["--ignore-names", ",".join(self.ignore_names)]
        cmd += ["--min-confidence", str(self.min_confidence)]
        cmd += self.extra_args
        cmd.append(".")

        raw_run = self._run(cmd, cwd=cwd_str)
        run = ToolRunResult(
            tool=raw_run.tool,
            cmd=raw_run.cmd,
            cwd=cwd_str,
            returncode=raw_run.returncode,
            duration_s=raw_run.duration_s,
            stdout=raw_run.stdout,
            stderr=raw_run.stderr,
            parsed_json=raw_run.parsed_json,
        )
        self.parse(run)
        return run

    def parse(self, result: ToolRunResult) -> None:  # noqa: D401
        """Placeholder hook for future schema integration."""
        return None


__all__ = ["VultureTool"]
