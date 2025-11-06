"""Parser for Qlty code quality results.

Qlty is a unified code quality platform that runs multiple linters and formatters.
It outputs results in SARIF (Static Analysis Results Interchange Format) format.

Functions
---------
qlty_sarif_to_models : Parse Qlty SARIF output to ORM models

Examples
--------
>>> sarif = {"runs": [{"results": [{"ruleId": "ripgrep:TODO"}]}]}
>>> scan, rows = qlty_sarif_to_models(sarif, cwd="/path")

See Also
--------
auditor.infra.tools.qlty : Qlty tool wrapper
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple, Union

from ..orm import QltyResult, ScanMetadata
from ._shared import (
    determine_root_label,
    ensure_abs,
    now_iso,
    relativize_path,
    strip_before_start_root,
)


def _coalesce_run(run: Union[str, Dict[str, Any]]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Extract SARIF payload and metadata from various input formats.
    
    Accepts:
    - raw SARIF JSON string
    - parsed SARIF dict
    - ToolRunResult-like dict with stdout/parsed_json
    
    Returns: (sarif_payload, extras)
    """
    extras: Dict[str, Any] = {}
    
    if isinstance(run, str):
        payload = json.loads(run)
    elif isinstance(run, dict):
        if run.get("parsed_json"):
            payload = run["parsed_json"]
        elif run.get("stdout"):
            payload = json.loads(run["stdout"])
        else:
            # Assume it's already the SARIF payload
            payload = run
        
        # Extract metadata
        for k in ("cmd", "cwd", "returncode", "duration_s"):
            if k in run:
                extras[k] = run[k]
    else:
        raise TypeError("Unsupported run type for qlty_sarif_to_models().")
    
    return payload, extras


def qlty_sarif_to_models(
    run: Union[str, Dict[str, Any]],
    *,
    cwd: Optional[str] = None,
    generated_at: Optional[str] = None,
    start_root: Optional[str] = None,
) -> Tuple["ScanMetadata", List["QltyResult"]]:
    """Parse Qlty SARIF JSON into ORM rows.
    
    Parameters
    ----------
    run : str or dict
        SARIF output from Qlty (JSON string or parsed dict)
    cwd : str, optional
        Working directory for path resolution
    generated_at : str, optional
        ISO timestamp for the scan. Defaults to current time.
    start_root : str, optional
        Project root for relative paths
    
    Returns
    -------
    tuple of (ScanMetadata, List[QltyResult])
        Scan metadata and list of findings
    
    Examples
    --------
    >>> sarif = {"runs": [{"results": [{"ruleId": "ripgrep:TODO"}]}]}
    >>> scan, rows = qlty_sarif_to_models(sarif, cwd="/project")
    >>> len(rows)
    1
    """
    ts = generated_at or now_iso()
    scan_row = ScanMetadata(scan_timestamp=ts)
    
    payload, extras = _coalesce_run(run)
    cwd = cwd or extras.get("cwd") or "."
    root_label = determine_root_label(cwd, start_root)
    
    # Parse SARIF structure
    runs = payload.get("runs", [])
    if not runs:
        return scan_row, []
    
    result_rows: List[QltyResult] = []
    
    # Process each run (Qlty may have multiple runs for different tools)
    for run_data in runs:
        tool_driver = run_data.get("tool", {}).get("driver", {})
        tool_name = tool_driver.get("name", "qlty")
        tool_version = tool_driver.get("semanticVersion") or tool_driver.get("version", "")
        
        # Build rule lookup
        rules = {rule["id"]: rule for rule in tool_driver.get("rules", [])}
        
        # Process results
        for result in run_data.get("results", []):
            result_rows.append(_create_qlty_result(
                scan_row=scan_row,
                result=result,
                rules=rules,
                tool_name=tool_name,
                tool_version=tool_version,
                root_label=root_label,
                cwd=cwd,
                start_root=start_root,
            ))
    
    return scan_row, result_rows


def _create_qlty_result(
    scan_row: ScanMetadata,
    result: Dict[str, Any],
    rules: Dict[str, Any],
    tool_name: str,
    tool_version: str,
    root_label: str,
    cwd: str,
    start_root: Optional[str],
) -> QltyResult:
    """Create a single QltyResult from SARIF data."""
    
    # Extract rule info
    rule_id = result.get("ruleId", "")
    rule = rules.get(rule_id, {})
    rule_name = rule.get("name", "")
    
    # Extract message
    msg = result.get("message", {})
    message_text = msg.get("text", "")
    
    # Level
    level = result.get("level", "")
    
    # Extract locations
    locations = result.get("locations", [])
    file_path = ""
    line_number = None
    end_line_number = None
    col_offset = None
    end_col_offset = None
    
    if locations:
        location = locations[0]  # Use first location
        phys_loc = location.get("physicalLocation", {})
        artifact = phys_loc.get("artifactLocation", {})
        region = phys_loc.get("region", {})
        
        # File path
        uri = artifact.get("uri", "")
        if uri:
            file_path = ensure_abs(uri, cwd)
            if start_root:
                file_path = strip_before_start_root(file_path, start_root)
        
        # Line and column info
        line_number = region.get("startLine")
        end_line_number = region.get("endLine")
        col_offset = region.get("startColumn")
        end_col_offset = region.get("endColumn")
    
    # Taxa (Qlty-specific categories)
    taxa = result.get("taxa", [])
    
    # Properties
    properties = result.get("properties")
    
    return QltyResult(
        scan=scan_row,
        root=root_label,
        file_path=file_path,
        line_number=line_number,
        end_line_number=end_line_number,
        col_offset=col_offset,
        end_col_offset=end_col_offset,
        rule_id=rule_id,
        rule_name=rule_name,
        level=level,
        message=message_text,
        taxa=taxa if taxa else None,
        tool_name=tool_name,
        tool_version=tool_version,
        properties=properties,
    )


__all__ = ["qlty_sarif_to_models"]
