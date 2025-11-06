# semgrep_parser_and_model.py
#
# Drop-in parser + model tweaks to mirror the vulture flow.
# Produces one ScanMetadata row + a "summary" SemgrepResult row + N "result" rows.
#
# Usage example is at the bottom.

"""Parser for Semgrep pattern matching results.

Semgrep is a fast, open-source static analysis tool for finding bugs and
enforcing code standards. This parser handles Semgrep's JSON output.

Functions
---------
semgrep_to_models : Parse Semgrep JSON output to ORM models

Examples
--------
>>> results = {"results": [{"check_id": "rule1", "path": "file.py"}]}
>>> scan, rows = semgrep_to_models(results, cwd="/path")

See Also
--------
auditor.infra.tools.semgrep : Semgrep tool wrapper
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple, Union

from ..orm import ScanMetadata, SemgrepResult
from ._shared import (
    determine_root_label,
    ensure_abs,
    now_iso,
    relativize_path,
    strip_before_start_root,
)


# ------------------------------
# Parser
# ------------------------------

def _coalesce_run(run: Union[str, Dict[str, Any]]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Accepts either:
    - raw semgrep JSON string (stdout)
    - already-parsed JSON dict (the semgrep payload itself)
    - a 'run' dict with keys like stdout/parsed_json/cmd/cwd/returncode/duration_s

    Returns: (payload, extras)
    """
    extras: Dict[str, Any] = {}
    if isinstance(run, str):
        payload = json.loads(run)
    elif isinstance(run, dict):
        if run.get("parsed_json"):
            payload = run["parsed_json"]
        elif run.get("stdout"):
            payload = json.loads(run["stdout"])  # stdout is a JSON string
        else:
            # Assume it's already the semgrep JSON payload
            payload = run
        for k in ("cmd", "cwd", "returncode", "duration_s"):
            if k in run:
                extras[k] = run[k]
    else:
        raise TypeError("Unsupported run type for semgrep_to_models().")
    return payload, extras


def _compute_rule_counts(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build lightweight counts from result list (by severity and by check_id)."""
    by_sev: Dict[str, int] = {}
    by_check: Dict[str, int] = {}
    for r in results:
        sev = ((r.get("extra") or {}).get("severity") or "UNKNOWN").upper()
        by_sev[sev] = by_sev.get(sev, 0) + 1
        cid = r.get("check_id")
        if cid:
            by_check[cid] = by_check.get(cid, 0) + 1
    return {"by_severity": by_sev, "by_check_id": by_check}


def semgrep_to_models(
    run: Union[str, Dict[str, Any]],
    *,
    cwd: Optional[str] = None,
    generated_at: Optional[str] = None,
    start_root: Optional[str] = None,
) -> Tuple["ScanMetadata", List["SemgrepResult"]]:
    """Parse Semgrep JSON into ORM rows.

    Returns (ScanMetadata, [SemgrepResult...]) where the list contains:
      - 1 summary row (row_type="summary")
      - N finding rows (row_type="result")
    """
    ts = generated_at or now_iso()
    scan_row = ScanMetadata(scan_timestamp=ts)

    payload, extras = _coalesce_run(run)
    version = payload.get("version")
    results = payload.get("results") or []
    errors = payload.get("errors") or []
    paths = (payload.get("paths") or {}).get("scanned") or []
    engine_requested = payload.get("engine_requested")
    time_block = payload.get("time") or {}
    profiling_times = time_block.get("profiling_times")


    rows: List[SemgrepResult] = []
    collected_relpaths: List[str] = []

    for item in results:
        path = item.get("path")
        start = item.get("start") or {}
        end = item.get("end") or {}
        extra = item.get("extra") or {}
        meta = (extra.get("metadata") or {}).copy()

        abs_path = ensure_abs(path, cwd)
        abs_path = strip_before_start_root(abs_path, start_root)
        rel = relativize_path(path, cwd) or path
        collected_relpaths.append(rel)

        rows.append(
            SemgrepResult(
                scan=scan_row,
                row_type="result",
                tool="semgrep",
                file_path=abs_path,
                root="",  # set after loop
                rule_id=extra.get("rule_id"),  # rarely present; keep for completeness
                check_id=item.get("check_id"),
                severity_text=extra.get("severity"),
                message=extra.get("message"),
                fix=extra.get("fix"),
                fingerprint=extra.get("fingerprint"),
                engine_kind=extra.get("engine_kind"),
                validation=item.get("validation_state") or extra.get("validation_state"),
                category=meta.get("category"),
                subcategory=meta.get("subcategory"),
                technology=meta.get("technology"),
                cwe=meta.get("cwe"),
                owasp=meta.get("owasp"),
                references=meta.get("references"),
                likelihood=meta.get("likelihood"),
                impact=meta.get("impact"),
                confidence_text=meta.get("confidence"),
                vulnerability_class=meta.get("vulnerability_class"),
                source_url=meta.get("source") or meta.get("source-rule-url"),
                shortlink=meta.get("shortlink"),
                metadata_blob=meta,
                line_number=int(start.get("line")) if start.get("line") is not None else None,
                end_line_number=int(end.get("line")) if end.get("line") is not None else None,
                # start_col=int(start.get("col")) if start.get("col") is not None else None,
                # end_col=int(end.get("col")) if end.get("col") is not None else None,
                # start_offset=int(start.get("offset")) if start.get("offset") is not None else None,
                # end_offset=int(end.get("offset")) if end.get("offset") is not None else None,
                col_offset=int(start.get("col")) if start.get("col") is not None else None,
                end_col_offset=int(end.get("col")) if end.get("col") is not None else None,
            )
        )

    # Single root label for all rows
    root_label = determine_root_label(cwd, collected_relpaths)
    try:
        for r in rows:
            r.root = start_root or root_label  # type: ignore[attr-defined]
    except Exception:
        # pydantic v2 frozen models compatibility
        rows = [
            (getattr(r, "model_copy", None) and r.model_copy(update={"root": start_root or root_label})) or r  # type: ignore[truthy-bool]
            for r in rows
        ]

    return scan_row, rows


__all__ = ["semgrep_to_models"]

