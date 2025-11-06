"""JSON utility functions for tool implementations.

This module provides JSON parsing and manipulation utilities used by
tool wrappers.

Functions
---------
safe_json_loads : Safely load JSON with error handling
normalize_json : Normalize JSON structure

Examples
--------
>>> from auditor.infra.tools.utils.json import safe_json_loads
>>> data = safe_json_loads('{"key": "value"}')

See Also
--------
auditor.infra.tools : Tool implementations
"""
from __future__ import annotations

import json
from typing import Any, Iterable, Iterator, Optional, Sequence, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - type hints only
    from auditor.core.models import ToolRunResult


def safe_json_loads(payload: str | bytes | None, default: Any = None) -> Any:
    """Best-effort JSON loader that never raises."""
    if payload is None:
        return default
    try:
        if isinstance(payload, bytes):
            payload = payload.decode("utf-8", "ignore")
        return json.loads(payload)
    except Exception:
        return default


def load_json_payload(result: "ToolRunResult", default: Any = None) -> Any:
    """
    Return a parsed JSON payload for a tool run.
    Prefers `ToolRunResult.parsed_json`, falling back to stdout parsing.
    """
    if result.parsed_json is not None:
        return result.parsed_json
    return safe_json_loads(result.stdout, default=default)


def load_json_stream(text: str | bytes | None) -> Iterator[Any]:
    """
    Iterate over JSON objects contained in a JSON-lines style stream.
    Silently skips malformed rows.
    """
    if text is None:
        return iter(())
    if isinstance(text, bytes):
        text = text.decode("utf-8", "ignore")

    def _iter() -> Iterator[Any]:
        for line in text.splitlines():
            line = line.strip()
            if not line or not (line.startswith("{") or line.startswith("[")):
                continue
            item = safe_json_loads(line, default=None)
            if item is None:
                continue
            if isinstance(item, Sequence) and not isinstance(
                item, (str, bytes, bytearray)
            ):
                for sub in item:
                    yield sub
            else:
                yield item

    return _iter()
