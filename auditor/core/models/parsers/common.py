from __future__ import annotations

"""Common data models for tool execution results.

This module defines the ToolRunResult model used to represent standardized
output from static analysis tool executions.

Classes
-------
ToolRunResult : Standardized tool execution result

Examples
--------
>>> result = ToolRunResult(
...     tool="bandit",
...     cmd=["bandit", "-f", "json", "file.py"],
...     cwd="/project",
...     returncode=0
... )

See Also
--------
auditor.application.orchestrator : Tool execution
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class ToolRunResult(BaseModel):
    tool: str
    cmd: List[str]
    cwd: str
    returncode: int
    duration_s: float
    stdout: str
    stderr: str
    parsed_json: Optional[Any] = None

    def to_dict(self) -> Dict[str, Any]:
        payload = self._model_dump()
        payload["stdout_bytes"] = len(self.stdout.encode("utf-8", "ignore"))
        payload["stderr_bytes"] = len(self.stderr.encode("utf-8", "ignore"))
        return payload

    def _model_dump(self) -> Dict[str, Any]:
        return self.model_dump()

class AuditResults(BaseModel):
    tool: str
    message: str
    start_line : Optional[int] = None
    end_line : Optional[int] = None
    start_col: Optional[int] = None
    end_col: Optional[int] = None
    file_path: Optional[str] = None
