"""Findings extraction and export utilities.

This module provides functionality to extract analysis findings from the database
and convert them to standardized formats for export and integration with other tools.

The module supports:
- Extracting findings from database to JSON format
- Converting Metabob analysis results to Auditor format
- Filtering by scan ID or tool
- Normalizing finding formats across different tools

Examples
--------
Extract all findings:
    >>> findings = extract_findings_to_json()
    >>> len(findings['findings'])
    42

Convert Metabob results:
    >>> metabob_data = load_metabob_json()
    >>> auditor_format = metabob_to_auditor(metabob_data)

See Also
--------
auditor.core.models.schema : Data models for findings
auditor.infra.db.utils : Database utilities
"""
from __future__ import annotations
from sqlalchemy.orm import Session

from auditor.core.models.schema import AuditResults
from auditor.infra.db.utils import get_session
from auditor.core.models.orm import (
    BanditResult,
    EslintResult,
    MypyResult,
    SemgrepResult,
    VultureResult,
    GitleaksResult,
    BiomeResult,
)
import json
from pathlib import Path
from typing import List, Optional, Dict, Type, Tuple, Set


def get_all_roots() -> List[str]:
    """Get all unique root paths from the database.
    
    Returns
    -------
    List[str]
        List of unique root paths sorted alphabetically.
    """
    roots: Set[str] = set()
    
    # Define all result models (excluding RadonResult - complexity metrics, not issues)
    models = [
        BanditResult, EslintResult, MypyResult, SemgrepResult,
        VultureResult, GitleaksResult, BiomeResult
    ]
    
    with get_session() as session:
        for model in models:
            try:
                distinct_roots = session.query(model.root).distinct().all()
                for (root,) in distinct_roots:
                    if root:
                        roots.add(root)
            except Exception:
                # Skip if model doesn't have root column or other issues
                continue
    
    return sorted(list(roots))


def match_root_by_folder(folder_name: str, available_roots: List[str]) -> Optional[str]:
    """Match a folder name to a full root path.
    
    Supports matching by the final folder name in the path, even if the
    full path has changed. For example, if folder_name is "project_01",
    it will match "/home/user/data/project_01" or "/backup/project_01".
    
    Parameters
    ----------
    folder_name : str
        Folder name or partial path to match (e.g., "project_01" or "data/project_01")
    available_roots : List[str]
        List of available root paths to match against
    
    Returns
    -------
    Optional[str]
        Matched root path, or None if no match found
        If multiple matches, returns the first one
    
    Examples
    --------
    >>> roots = ["/home/user/A", "/home/user/B/C"]
    >>> match_root_by_folder("C", roots)
    '/home/user/B/C'
    >>> match_root_by_folder("B/C", roots)
    '/home/user/B/C'
    """
    # Normalize the folder name
    folder_name = folder_name.strip().strip('/')
    
    # Try exact match first
    if folder_name in available_roots:
        return folder_name
    
    # Try to match by ending path components
    folder_parts = folder_name.split('/')
    
    for root in available_roots:
        root_parts = root.strip('/').split('/')
        
        # Check if the folder_parts match the end of root_parts
        if len(folder_parts) <= len(root_parts):
            if root_parts[-len(folder_parts):] == folder_parts:
                return root
    
    return None


def extract_findings_to_json(
    *,
    scan_id: Optional[int] = None,
    root: Optional[str] = None,
) -> dict:
    """Extract findings from database and return as JSON structure.

    Queries all tool result tables and aggregates findings into a unified
    JSON format suitable for export or further processing.

    Parameters
    ----------
    scan_id : int, optional
        If provided, only extract findings from this specific scan.
        If None, extract findings from all scans. Default is None.
    root : str, optional
        If provided, only extract findings from this root path.
        Can be a full path or just the final folder name(s).
        Example: "project_01" or "data/project_01"
        If None, extract findings from all roots. Default is None.

    Returns
    -------
    dict
        Dictionary with keys:
        - 'name': str, always 'auditor'
        - 'findings': list[dict], list of finding dictionaries
        - 'root': str or None, the root filter used (if any)

    Notes
    -----
    The function queries the following tool result tables:
    - Semgrep, Bandit, Mypy, Vulture, ESLint, Gitleaks, Biome
    
    Note: Radon is excluded as it provides complexity analytics, not issues.

    Each finding includes:
    - tool: Tool name
    - message: Finding message
    - start_line, end_line: Line number range
    - start_col, end_col: Column offset range
    - file_path: Path to affected file

    Examples
    --------
    Extract all findings:
        >>> result = extract_findings_to_json()
        >>> len(result['findings'])
        150

    Extract findings from specific scan:
        >>> result = extract_findings_to_json(scan_id=42)
        >>> result['name']
        'auditor'
    
    Extract findings from specific root:
        >>> result = extract_findings_to_json(root="project_01")
        >>> result['root']
        '/full/path/to/project_01'
    """

    TOOL_ORM: Dict[str, Type] = {
        "semgrep": SemgrepResult,
        "bandit": BanditResult,
        "mypy": MypyResult,
        "vulture": VultureResult,
        "eslint": EslintResult,
        "gitleaks": GitleaksResult,
        "biome": BiomeResult,
        # Note: RadonResult excluded - complexity analytics, not issues
    }

    # Resolve root if provided
    resolved_root = None
    if root:
        available_roots = get_all_roots()
        resolved_root = match_root_by_folder(root, available_roots)
        if not resolved_root:
            # If no match, try using it as-is
            resolved_root = root

    findings: List[dict] = []

    with get_session() as session:
        for tool_name, model in TOOL_ORM.items():
            q = session.query(model)

            if scan_id is not None:
                q = q.filter(model.scan_id == scan_id)
            
            if resolved_root is not None:
                # Filter by root
                q = q.filter(model.root == resolved_root)

            # Project only the columns we need; they exist on ResultsBase + message on each model
            try:
                cols = (
                    model.message,
                    model.line_number,
                    model.end_line_number,
                    model.col_offset,
                    model.end_col_offset,
                    model.file_path,
                )

                rows: List[Tuple] = q.with_entities(*cols).all()

                for (message, line, end_line, col, end_col, file_path) in rows:
                    findings.append(AuditResults(
                        tool=tool_name,
                        message=message or "",
                        start_line=line,
                        end_line=end_line,
                        start_col=col,
                        end_col=end_col,
                        file_path=file_path or "",
                    ).model_dump())
            except Exception:
                # Skip models that don't have message field (e.g., RadonResult)
                continue

    output = {
        "name": "auditor",
        "findings": findings,
        "root": resolved_root,
    }

    return output


def metabob_to_auditor(json_data: dict) -> dict:
    """Convert Metabob analysis results to Auditor format.

    Transforms Metabob-specific JSON structure into the standardized Auditor
    findings format for unified reporting and analysis.

    Parameters
    ----------
    json_data : dict
        Metabob analysis JSON with 'entries' key containing findings.

    Returns
    -------
    dict
        Dictionary with keys:
        - 'name': str, always 'auditor'
        - 'findings': list[dict], converted findings

    Notes
    -----
    Only findings with severity 'HIGH' or 'MEDIUM' are included in the output.
    Each finding combines category and description into the message field.

    The conversion maps:
    - Metabob 'entries' → Auditor 'findings'
    - Metabob 'startLine'/'endLine' → Auditor start_line/end_line
    - Metabob 'path' → Auditor file_path
    - Category + Description → message

    Examples
    --------
    >>> metabob_data = {
    ...     "entries": [{
    ...         "category": "Security",
    ...         "description": "SQL injection risk",
    ...         "severity": "HIGH",
    ...         "startLine": 42,
    ...         "endLine": 42,
    ...         "path": "app.py"
    ...     }]
    ... }
    >>> result = metabob_to_auditor(metabob_data)
    >>> len(result['findings'])
    1
    >>> result['findings'][0]['tool']
    'metabob'
    """
    findings: List[dict] = []

    for finding in json_data.get("entries", []):
        if finding.get("severity") in ["HIGH", "MEDIUM"]:
            message = f" Category: {finding.get('category','')} \n  Description: {finding.get('description','')}"
            findings.append(AuditResults(
                tool="metabob",
                message=message,
                start_line=finding.get("startLine"),
                end_line=finding.get("endLine"),
                start_col=finding.get("start_col",0),
                end_col=finding.get("end_col",0),
                file_path=finding.get("path", ""),
            ).model_dump())

    output = {
        "name": "auditor",
        "findings": findings,
    }

    return output