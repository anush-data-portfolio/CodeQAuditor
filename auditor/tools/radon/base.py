from __future__ import annotations

from pathlib import Path
from typing import Dict, Union

from auditor.models import ToolRunResult

from ..base import AuditTool
from ..utils import load_json_payload


class RadonTool(AuditTool):
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

    def build_cmd(self, path: str):
        # Only used by `is_installed`
        return ["radon", "cc", "-j", "."]

    def audit(self, path: Union[str, Path]) -> ToolRunResult:
        root = Path(path).resolve()

        runs: Dict[str, ToolRunResult] = {
            "cc": self._run(["radon", "cc", "-s", "-j", "."], cwd=str(root)),
            "mi": self._run(["radon", "mi", "-j", "."], cwd=str(root)),
            "hal": self._run(["radon", "hal", "-j", "."], cwd=str(root)),
            "raw": self._run(["radon", "raw", "-j", "."], cwd=str(root)),
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
            cwd=str(root),
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
