"""Parser for Snyk Code SAST results.

Snyk Code is a static application security testing (SAST) tool that detects
security vulnerabilities and code quality issues in source code. It outputs
results in SARIF (Static Analysis Results Interchange Format) format.

Functions
---------
snyk_sarif_to_models : Parse Snyk SARIF output to ORM models

Examples
--------
>>> sarif = {"runs": [{"results": [{"ruleId": "javascript/DOMXSS"}]}]}
>>> scan, rows = snyk_sarif_to_models(sarif, cwd="/path")

See Also
--------
auditor.infra.tools.snyk : Snyk tool wrapper
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple, Union

from ..orm import ScanMetadata, SnykResult
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
        raise TypeError("Unsupported run type for snyk_sarif_to_models().")
    
    return payload, extras


def snyk_sarif_to_models(
    run: Union[str, Dict[str, Any]],
    *,
    cwd: Optional[str] = None,
    generated_at: Optional[str] = None,
    start_root: Optional[str] = None,
) -> Tuple["ScanMetadata", List["SnykResult"]]:
    """Parse Snyk SARIF JSON into ORM rows.
    
    Parameters
    ----------
    run : str or dict
        SARIF output from Snyk (JSON string or parsed dict)
    cwd : str, optional
        Working directory for path resolution
    generated_at : str, optional
        ISO timestamp for the scan. Defaults to current time.
    start_root : str, optional
        Project root for relative paths
    
    Returns
    -------
    tuple of (ScanMetadata, List[SnykResult])
        Scan metadata and list of findings
    
    Examples
    --------
    >>> sarif = {"runs": [{"results": [{"ruleId": "python/NoHardcodedPasswords"}]}]}
    >>> scan, rows = snyk_sarif_to_models(sarif, cwd="/project")
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
    
    result_rows: List[SnykResult] = []
    
    # Process first run (Snyk typically outputs one run)
    run_data = runs[0]
    tool_driver = run_data.get("tool", {}).get("driver", {})
    rules = {rule["id"]: rule for rule in tool_driver.get("rules", [])}
    
    # Process results
    for result in run_data.get("results", []):
        rule_id = result.get("ruleId")
        rule_index = result.get("ruleIndex")
        
        # Get rule metadata
        rule = rules.get(rule_id, {}) if rule_id else {}
        if rule_index is not None and not rule:
            # Fallback: get rule by index
            rules_list = tool_driver.get("rules", [])
            if 0 <= rule_index < len(rules_list):
                rule = rules_list[rule_index]
        
        # Extract message
        msg = result.get("message", {})
        message_text = msg.get("text", "")
        message_markdown = msg.get("markdown", "")
        
        # Extract locations
        locations = result.get("locations", [])
        if not locations:
            # Create result without specific location
            result_rows.append(_create_snyk_result(
                scan_row=scan_row,
                result=result,
                rule=rule,
                rule_id=rule_id,
                message_text=message_text,
                message_markdown=message_markdown,
                location=None,
                root_label=root_label,
                cwd=cwd,
                start_root=start_root,
            ))
        else:
            # Create one result per location
            for location in locations:
                result_rows.append(_create_snyk_result(
                    scan_row=scan_row,
                    result=result,
                    rule=rule,
                    rule_id=rule_id,
                    message_text=message_text,
                    message_markdown=message_markdown,
                    location=location,
                    root_label=root_label,
                    cwd=cwd,
                    start_root=start_root,
                ))
    
    return scan_row, result_rows


def _create_snyk_result(
    scan_row: ScanMetadata,
    result: Dict[str, Any],
    rule: Dict[str, Any],
    rule_id: Optional[str],
    message_text: str,
    message_markdown: str,
    location: Optional[Dict[str, Any]],
    root_label: str,
    cwd: str,
    start_root: Optional[str],
) -> SnykResult:
    """Create a single SnykResult from SARIF data."""
    
    # Extract location info
    file_path = ""
    line_number = None
    end_line_number = None
    col_offset = None
    end_col_offset = None
    
    if location:
        phys_loc = location.get("physicalLocation", {})
        artifact = phys_loc.get("artifactLocation", {})
        region = phys_loc.get("region", {})
        
        # File path
        uri = artifact.get("uri", "")
        if uri:
            # Handle %SRCROOT% placeholder
            uri = uri.replace("%SRCROOT%/", "")
            file_path = ensure_abs(uri, cwd)
            if start_root:
                file_path = strip_before_start_root(file_path, start_root)
        
        # Line and column info
        line_number = region.get("startLine")
        end_line_number = region.get("endLine")
        col_offset = region.get("startColumn")
        end_col_offset = region.get("endColumn")
    
    # Extract rule metadata
    rule_name = rule.get("name", "")
    short_desc = rule.get("shortDescription", {})
    help_data = rule.get("help", {})
    properties = rule.get("properties", {})
    
    # Fingerprints
    fingerprints = result.get("fingerprints", {})
    fingerprint = (
        fingerprints.get("identity") or
        fingerprints.get("snyk/asset/finding/v1") or
        fingerprints.get("0") or
        fingerprints.get("1") or
        ""
    )
    
    # Level/severity
    level = result.get("level", "")
    
    # Result properties
    result_props = result.get("properties", {})
    priority_score = result_props.get("priorityScore")
    priority_factors = result_props.get("priorityScoreFactors")
    is_autofixable = result_props.get("isAutofixable")
    
    # Code flows
    code_flows = result.get("codeFlows", [])
    
    # Rule properties
    tags = properties.get("tags", [])
    categories = properties.get("categories", [])
    cwe = properties.get("cwe", [])
    precision = properties.get("precision", "")
    example_fixes = properties.get("exampleCommitFixes", [])
    
    # Help text
    help_text = help_data.get("text", "")
    help_markdown = help_data.get("markdown", "")
    
    # Default configuration
    default_config = rule.get("defaultConfiguration", {})
    default_level = default_config.get("level", "")
    
    return SnykResult(
        scan=scan_row,
        root=start_root,
        file_path=file_path,
        line_number=line_number,
        end_line_number=end_line_number,
        col_offset=col_offset,
        end_col_offset=end_col_offset,
        rule_id=rule_id,
        rule_name=rule_name,
        fingerprint=fingerprint,
        level=level or default_level,
        message=message_text,
        message_markdown=message_markdown,
        cwe=cwe if cwe else None,
        categories=categories if categories else None,
        tags=tags if tags else None,
        priority_score=priority_score,
        priority_factors=priority_factors if priority_factors else None,
        is_autofixable=is_autofixable,
        precision=precision,
        code_flows=code_flows if code_flows else None,
        help_text=help_text,
        help_markdown=help_markdown,
        example_fixes=example_fixes if example_fixes else None,
    )


__all__ = ["snyk_sarif_to_models"]
