from __future__ import annotations

from typing import List, Optional, Tuple, Union

from pydantic import BaseModel, ConfigDict

from ..orm import BanditResult, ScanMetadata
from ._shared import determine_root, now_iso, relativize_path, validate


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
) -> Tuple[ScanMetadata, List[BanditResult]]:
    """
    Validate Bandit payload (dict or list-of-results) and produce ORM rows.
    """
    scan = _coerce_bandit_scan(raw, generated_at)

    file_paths = [relativize_path(r.filename, cwd) or r.filename for r in scan.results]
    root = determine_root(cwd, file_paths)

    scan_row = ScanMetadata(scan_timestamp=scan.generated_at or now_iso())

    rows: List[BanditResult] = []
    for r in scan.results:
        end_ln = max(r.line_range) if r.line_range else r.line_number
        rel_filename = relativize_path(r.filename, cwd)
        rows.append(
            BanditResult(
                scan=scan_row,
                file_path=rel_filename or r.filename,
                root=root,
                line_number=r.line_number,
                end_line_number=end_ln,
                col_offset=r.col_offset,
                end_col_offset=r.end_col_offset,
                code=r.code,
                issue_confidence=r.issue_confidence,
                issue=(r.issue_text or None),
                rule=":".join([x for x in [r.test_id, r.test_name] if x]),
            )
        )
    return scan_row, rows


__all__ = [
    "BanditResultModel",
    "BanditScan",
    "bandit_json_to_models",
]
