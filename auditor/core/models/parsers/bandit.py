"""Parser for Bandit security analysis results.

Bandit is a Python security linter that identifies common security issues.
This parser converts Bandit's JSON output format into database models.

Functions
---------
bandit_json_to_models : Parse Bandit JSON output to ORM models

Examples
--------
>>> results = [{"test_id": "B101", "issue_text": "Use of assert"}]
>>> scan, rows = bandit_json_to_models(results, cwd="/path")

See Also
--------
auditor.infra.tools.bandit : Bandit tool wrapper
"""
from __future__ import annotations

from typing import List, Optional, Tuple, Union

from pydantic import BaseModel, ConfigDict

from ..orm import BanditResult, ScanMetadata
from ._shared import (
    now_iso,
    determine_root_label,
    relativize_path,
    ensure_abs,
    strip_before_start_root,
    validate,
)


class IssueCWE(BaseModel):
    id: Optional[int] = None
    link: Optional[str] = None


class BanditResultModel(BaseModel):
    code: Optional[str] = None
    col_offset: Optional[int] = None
    end_col_offset: Optional[int] = None
    filename: str
    issue_confidence: Optional[str] = None
    issue_cwe: Optional[IssueCWE] = None
    issue_severity: Optional[str] = None
    issue_text: Optional[str] = None
    line_number: Optional[int] = None
    line_range: Optional[List[int]] = None
    more_info: Optional[str] = None
    test_id: Optional[str] = None
    test_name: Optional[str] = None


class BanditScan(BaseModel):
    generated_at: Optional[str] = None
    results: List[BanditResultModel] = []
    model_config = ConfigDict(extra="ignore")


def _coerce_bandit_scan(
    raw: Union[dict, list], generated_at: Optional[str]
) -> BanditScan:
    """Accept either full Bandit dict or plain results list."""
    if isinstance(raw, list):
        results = [validate(BanditResultModel, item) for item in raw]
        return BanditScan(
            generated_at=generated_at or now_iso(),
            results=results,
        )
    if isinstance(raw, dict):
        scan = validate(BanditScan, raw)
        if not scan.generated_at:
            scan.generated_at = generated_at or now_iso()
        return scan
    raise TypeError(f"Unsupported bandit payload type: {type(raw)!r}")


def bandit_json_to_models(
    raw: Union[dict, list],
    generated_at: Optional[str] = None,
    *,
    cwd: Optional[str] = None,
    start_root: Optional[str] = None,
) -> Tuple["ScanMetadata", List["BanditResult"]]:
    """
    Validate Bandit payload (dict or list-of-results) and produce ORM rows.
    Uses shared path utilities for consistent paths and root labeling.
    """
    scan = _coerce_bandit_scan(raw, generated_at)

    # Build relative paths once to compute a stable root label.
    rel_paths: List[str] = [
        relativize_path(r.filename, cwd) or r.filename for r in scan.results
    ]
    root_label = determine_root_label(cwd, rel_paths)

    scan_row = ScanMetadata(scan_timestamp=scan.generated_at or now_iso())

    rows: List[BanditResult] = []
    for r in scan.results:
        end_ln = max(r.line_range) if getattr(r, "line_range", None) else r.line_number

        # Absolute path, then optionally strip leading segments up to start_root.
        abs_path = ensure_abs(r.filename, cwd)
        abs_path = strip_before_start_root(abs_path, start_root)

        rows.append(
            BanditResult(
                scan=scan_row,
                file_path=abs_path,
                root=start_root,
                line_number=r.line_number,
                end_line_number=end_ln,
                col_offset=r.col_offset,
                end_col_offset=r.end_col_offset,
                code=r.code,
                issue_confidence=r.issue_confidence,
                message=(r.issue_text or None),
                rule=":".join([x for x in [r.test_id, r.test_name] if x]),
            )
        )


    return scan_row, rows
    

__all__ = [
    "BanditResultModel",
    "BanditScan",
    "bandit_json_to_models",
]
