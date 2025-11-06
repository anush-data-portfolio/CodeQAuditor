"""Parser for Bearer SAST results.

Bearer is a code security and privacy scanner that detects sensitive data flows
and security vulnerabilities. It outputs results in JSON format with severity
levels (high, medium, low, critical).

Functions
---------
bearer_json_to_models : Parse Bearer JSON output to ORM models

Examples
--------
>>> results = {"high": [{"id": "rule1", "title": "Issue"}], "low": []}
>>> scan, rows = bearer_json_to_models(results, cwd="/path")

See Also
--------
auditor.infra.tools.bearer : Bearer tool wrapper
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple, Union

from ..orm import BearerResult, ScanMetadata
from ._shared import (
    determine_root_label,
    ensure_abs,
    now_iso,
    relativize_path,
    strip_before_start_root,
)


def bearer_json_to_models(
    raw: Union[dict, str],
    generated_at: Optional[str] = None,
    *,
    cwd: Optional[str] = None,
    start_root: Optional[str] = None,
) -> Tuple["ScanMetadata", List["BearerResult"]]:
    """
    Convert Bearer JSON output to ORM models.
    
    Bearer output format groups findings by severity level:
    {
      "high": [...],
      "medium": [...],
      "low": [...],
      "critical": [...]
    }
    
    Parameters
    ----------
    raw : dict or str
        Raw JSON output from Bearer
    generated_at : str, optional
        ISO timestamp for the scan. Defaults to current time.
    cwd : str, optional
        Working directory for path resolution
    start_root : str, optional
        Project root for relative paths
    
    Returns
    -------
    tuple of (ScanMetadata, List[BearerResult])
        Scan metadata and list of findings
    
    Examples
    --------
    >>> raw = {"high": [{"id": "rule1", "line_number": 5}]}
    >>> scan, rows = bearer_json_to_models(raw, cwd="/project")
    >>> len(rows)
    1
    """
    import json
    
    # Parse if string
    if isinstance(raw, str):
        data = json.loads(raw)
    else:
        data = raw
    
    ts = generated_at or now_iso()
    scan_row = ScanMetadata(scan_timestamp=ts)
    
    cwd = cwd or "."
    root_label = determine_root_label(cwd, start_root)
    
    result_rows: List[BearerResult] = []
    
    # Bearer groups results by severity
    severity_levels = ["critical", "high", "medium", "low"]
    
    for severity in severity_levels:
        findings = data.get(severity, [])
        
        for finding in findings:
            result = _create_bearer_result(
                scan_row=scan_row,
                finding=finding,
                severity=severity,
                root_label=root_label,
                cwd=cwd,
                start_root=start_root,
            )
            result_rows.append(result)
    
    return scan_row, result_rows


def _create_bearer_result(
    scan_row: ScanMetadata,
    finding: Dict[str, Any],
    severity: str,
    root_label: str,
    cwd: str,
    start_root: Optional[str],
) -> BearerResult:
    """Create a single BearerResult from Bearer finding data."""
    
    # Basic identification
    rule_id = finding.get("id", "")
    title = finding.get("title", "")
    fingerprint = finding.get("fingerprint", "")
    old_fingerprint = finding.get("old_fingerprint", "")
    
    # Description and documentation
    description = finding.get("description", "")
    documentation_url = finding.get("documentation_url", "")
    
    # CWE and category
    cwe_ids = finding.get("cwe_ids", [])
    category_groups = finding.get("category_groups", [])
    
    # Data type (for data leakage detections)
    data_type = finding.get("data_type")
    
    # File paths
    full_filename = finding.get("full_filename", "")
    filename_relative = finding.get("filename", "")
    
    # Resolve file path
    file_path = ""
    if full_filename:
        file_path = ensure_abs(full_filename, cwd)
        if start_root:
            file_path = strip_before_start_root(file_path, start_root)
    elif filename_relative:
        file_path = ensure_abs(filename_relative, cwd)
        if start_root:
            file_path = strip_before_start_root(file_path, start_root)
    
    # Line numbers
    line_number = finding.get("line_number")
    parent_line_number = finding.get("parent_line_number")
    
    # Source and sink (for data flow)
    source = finding.get("source")
    sink = finding.get("sink")
    
    # Column information from source/sink
    col_offset = None
    end_col_offset = None
    end_line_number = None
    
    if source:
        start_col = source.get("column", {}).get("start")
        end_col = source.get("column", {}).get("end")
        if start_col:
            col_offset = start_col
        if end_col:
            end_col_offset = end_col
        
        # Check if source has line info
        source_start = source.get("start")
        source_end = source.get("end")
        if source_start and not line_number:
            line_number = source_start
        if source_end:
            end_line_number = source_end
    
    # Code extract
    code_extract = finding.get("code_extract", "")
    
    return BearerResult(
        scan=scan_row,
        root=root_label,
        file_path=file_path,
        line_number=line_number,
        end_line_number=end_line_number,
        col_offset=col_offset,
        end_col_offset=end_col_offset,
        rule_id=rule_id,
        title=title,
        fingerprint=fingerprint,
        old_fingerprint=old_fingerprint,
        severity=severity,
        description=description,
        message=title,  # Use title as message
        cwe_ids=cwe_ids if cwe_ids else None,
        category_groups=category_groups if category_groups else None,
        data_type=data_type,
        source=source,
        sink=sink,
        parent_line_number=parent_line_number,
        code_extract=code_extract,
        filename_relative=filename_relative,
        documentation_url=documentation_url,
    )


__all__ = ["bearer_json_to_models"]
