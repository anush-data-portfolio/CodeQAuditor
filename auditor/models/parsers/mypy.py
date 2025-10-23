from __future__ import annotations

import json
from typing import List, Optional, Tuple

from pydantic import BaseModel

from ..orm import MypyResult, ScanMetadata
from ._shared import determine_root, now_iso, relativize_path, validate


class MypyItem(BaseModel):
    file: str
    line: int
    column: int
    message: str
    hint: Optional[str] = None
    code: Optional[str] = None
    severity: Optional[str] = None


def parse_mypy_ndjson(ndjson_text: str) -> List[MypyItem]:
    """
    Parse a string that contains one JSON object per line (NDJSON).
    Blank lines are ignored.
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
) -> Tuple[ScanMetadata, List[MypyResult]]:
    """
    Convert mypy/pyright-like NDJSON string → ORM rows.
    """
    items = parse_mypy_ndjson(ndjson_text)
    file_paths = [relativize_path(it.file, cwd) or it.file for it in items]
    root = determine_root(cwd, file_paths)
    ts = generated_at or now_iso()

    scan_row = ScanMetadata(scan_timestamp=ts)

    rows: List[MypyResult] = []
    for it in items:
        rel_file = relativize_path(it.file, cwd)
        rows.append(
            MypyResult(
                scan=scan_row,
                file_path=rel_file,
                root=root,
                line_number=it.line,
                end_line_number=it.line,
                col_offset=it.column,
                end_col_offset=None,
                message=it.message,
                hint=it.hint,
                code=it.code,
                severity=it.severity,
            )
        )

    return scan_row, rows


__all__ = [
    "MypyItem",
    "parse_mypy_ndjson",
    "mypy_ndjson_to_models",
]
