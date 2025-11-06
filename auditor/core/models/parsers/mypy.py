"""Parser for Mypy static type checking results.

Mypy is a static type checker for Python. This parser handles both NDJSON
and text output formats from Mypy.

Functions
---------
mypy_ndjson_to_models : Parse Mypy NDJSON output to ORM models
parse_mypy_ndjson : Parse raw NDJSON text

Examples
--------
>>> output = '{"file": "test.py", "line": 10, "message": "error"}\n'
>>> scan, rows = mypy_ndjson_to_models(output, cwd="/path")

See Also
--------
auditor.infra.tools.mypy : Mypy tool wrapper
"""
from __future__ import annotations

import json
from typing import List, Optional, Tuple

from pydantic import BaseModel

from ..orm import MypyResult, ScanMetadata
from ._shared import (
    now_iso,
    determine_root_label,
    relativize_path,
    ensure_abs,
    validate,
    strip_before_start_root,
)


class MypyItem(BaseModel):
    file: str
    line: int
    column: int
    message: str
    hint: Optional[str] = None
    code: Optional[str] = None
    severity: Optional[str] = None  # "error" | "warning" | "note" | None


def parse_mypy_ndjson(ndjson_text: str) -> List[MypyItem]:
    """
    Parse NDJSON (one JSON object per line). Blank / bad lines are ignored.
    """
    items: List[MypyItem] = []
    for line in ndjson_text.splitlines():
        text = line.strip()
        if not text:
            continue
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            continue
        items.append(validate(MypyItem, obj))
    return items


def mypy_ndjson_to_models(
    ndjson_text: str,
    generated_at: Optional[str] = None,
    *,
    cwd: Optional[str] = None,
    start_root: Optional[str] = None,
) -> Tuple["ScanMetadata", List["MypyResult"]]:
    """
    Convert mypy NDJSON → ORM rows. Uses shared path helpers and assigns a stable root.
    """
    items = parse_mypy_ndjson(ndjson_text)

    # Build relative paths once to compute a stable root label.
    rel_paths: List[str] = [relativize_path(it.file, cwd) or it.file for it in items]
    root_label = determine_root_label(cwd, rel_paths)

    ts = generated_at or now_iso()
    scan_row = ScanMetadata(scan_timestamp=ts)

    rows: List[MypyResult] = []
    for it in items:
        # Absolute path, then optionally strip leading segments up to start_root
        abs_path = ensure_abs(it.file, cwd)
        abs_path = strip_before_start_root(abs_path, start_root)

        rows.append(
            MypyResult(
                scan=scan_row,
                file_path=abs_path,
                root=start_root or root_label,        # ← keep root stable like other parsers
                line_number=it.line,
                end_line_number=it.line,              # mypy doesn't provide an explicit end line here
                col_offset=it.column,
                end_col_offset=None,                  # unknown
                message=it.message,
                hint=it.hint,
                code=it.code,
                severity=(it.severity or None),       # pass through as provided (e.g., "error")
            )
        )

    return scan_row, rows


__all__ = [
    "MypyItem",
    "parse_mypy_ndjson",
    "mypy_ndjson_to_models",
]
