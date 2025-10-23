from typing import Any, Dict, List, Optional, Sequence, Union, cast
from pathlib import Path

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
