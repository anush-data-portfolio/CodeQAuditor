"""Radon code metrics tool implementation.

This module implements the Radon tool wrapper for computing code complexity
and other metrics for Python code.

Classes
-------
RadonTool : Radon tool implementation

Examples
--------
>>> tool = RadonTool()
>>> result = tool.audit("myfile.py")

See Also
--------
auditor.infra.tools.base : Base tool class
auditor.core.models.parsers.radon : Result parser
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, Union

from auditor.core.models import ToolRunResult

from ..base import CommandAuditTool
from ..utils import load_json_payload


class RadonTool(CommandAuditTool):
    """
    Execute the Radon metrics suite (cc/mi/hal/raw) and return a combined ToolRunResult.
    The combined result exposes a parsed_json payload shaped as:

        {
            "cc": <raw cc JSON>,
            "mi": <raw mi JSON>,
            "hal": <raw hal JSON>,
            "raw": <raw raw JSON>,
        }
    """

    @property
    def name(self) -> str:
        return "radon"

    def build_cmd(self, metric: str, path: str):
        return ["radon", metric, "-j", path]

    def audit(self, path: Union[str, Path]) -> ToolRunResult:
        path_str = str(Path(path).resolve())
        cwd_str = str(Path(path_str).parent)


        runs: Dict[str, ToolRunResult] = {
            "cc": self._run(self.build_cmd("cc", path_str), cwd=cwd_str),
            "mi": self._run(self.build_cmd("mi", path_str), cwd=cwd_str),
            "hal": self._run(self.build_cmd("hal", path_str), cwd=cwd_str),
            "raw": self._run(self.build_cmd("raw", path_str), cwd=cwd_str),
        }

        payload = {
            kind: load_json_payload(run, default={}) for kind, run in runs.items()
        }

        stdout_bundle = "\n\n".join(run.stdout for run in runs.values() if run.stdout)
        stderr_bundle = "\n\n".join(run.stderr for run in runs.values() if run.stderr)
        total_duration = sum(run.duration_s for run in runs.values())
        max_returncode = max(run.returncode for run in runs.values())

        combined = ToolRunResult(
            tool=self.name,
            cmd=["radon", "<cc+mi+hal+raw>"],
            cwd=cwd_str,
            returncode=max_returncode,
            duration_s=total_duration,
            stdout=stdout_bundle,
            stderr=stderr_bundle,
            parsed_json=payload,
        )

        self.parse(combined)
        return combined

    def parse(self, result: ToolRunResult) -> None:  # noqa: D401 - intentional no-op
        """Placeholder hook for future schema integration."""
        return None


__all__ = ["RadonTool"]
