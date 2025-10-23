from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any, List, Optional, Union

from auditor.models import ToolRunResult

from ..base import AuditTool


class MypyTool(AuditTool):
    """
    Run mypy with configurable flags and return the raw ToolRunResult.
    """

    @property
    def name(self) -> str:
        return "mypy"

    def __init__(
        self,
        python_version: Optional[str] = "3.12",
        ignore_missing_imports: bool = True,
        follow_imports: str = "silent",
        install_types: bool = False,
        strict: bool = False,
        collapse_notes: bool = True,
        drop_external_notes: bool = True,
        **kw: Any,
    ) -> None:
        super().__init__(**kw)
        self.python_version = python_version
        self.ignore_missing_imports = ignore_missing_imports
        self.follow_imports = follow_imports
        self.install_types = install_types
        self.strict = strict
        self.collapse_notes = collapse_notes
        self.drop_external_notes = drop_external_notes

    def build_cmd(self, path: str) -> List[str]:
        return ["mypy", "--output", "json", "."]

    def audit(self, path: Union[str, Path]) -> ToolRunResult:
        path_obj = Path(path).absolute()

        cwd_str = path if isinstance(path, str) else str(path_obj)

        raw_run: Optional[ToolRunResult] = None

        with tempfile.TemporaryDirectory(prefix="mypy-") as tmp:
            reports_dir = Path(tmp) / "reports"
            cache_dir = Path(tmp) / "cache"
            reports_dir.mkdir(parents=True, exist_ok=True)
            cache_dir.mkdir(parents=True, exist_ok=True)

            cmd: List[str] = [
                "mypy",
                ".",
                "--output",
                "json",
                "--no-site-packages",
                "--explicit-package-bases",
                "--show-error-end",
                "--show-column-numbers",
                "--sqlite-cache",
                "--cache-dir",
                str(cache_dir),
                "--linecoverage-report",
                str(reports_dir),
                "--linecount-report",
                str(reports_dir),
                "--any-exprs-report",
                str(reports_dir),
                "--txt-report",
                str(reports_dir),
            ]
            if self.python_version:
                cmd += ["--python-version", self.python_version]
            if self.ignore_missing_imports:
                cmd += ["--ignore-missing-imports"]
            if self.follow_imports:
                cmd += ["--follow-imports", self.follow_imports]
            if self.strict:
                cmd += ["--strict"]
            if self.install_types:
                cmd += ["--install-types", "--non-interactive"]

            prev_cache_env = self.env.get("MYPY_CACHE_DIR")
            self.env["MYPY_CACHE_DIR"] = str(cache_dir)
            try:
                raw_run = self._run(cmd, cwd=cwd_str)
            finally:
                if prev_cache_env is None:
                    self.env.pop("MYPY_CACHE_DIR", None)
                else:
                    self.env["MYPY_CACHE_DIR"] = prev_cache_env

        if raw_run is None:
            raise RuntimeError("mypy invocation did not produce a ToolRunResult")

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

    def parse(self, result: ToolRunResult) -> None:  # noqa: D401 - intentional no-op
        """Placeholder hook for future schema integration."""
        return None


__all__ = ["MypyTool"]
