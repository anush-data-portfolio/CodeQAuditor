"""Parser for Gitleaks secret scanning results.

Gitleaks is a SAST tool for detecting hardcoded secrets like passwords,
API keys, and tokens in git repos, directories, and files.

Functions
---------
gitleaks_json_to_models : Parse Gitleaks JSON output to ORM models

Examples
--------
>>> results = [{"RuleID": "aws-key", "File": "config.py", "StartLine": 10}]
>>> scan, rows = gitleaks_json_to_models(results, cwd="/path")

See Also
--------
auditor.infra.tools.gitleaks : Gitleaks tool wrapper
"""
from __future__ import annotations

from typing import List, Optional, Tuple, Union

from pydantic import BaseModel, ConfigDict, Field

from ..orm import GitleaksResult, ScanMetadata
from ._shared import (
    now_iso,
    determine_root_label,
    relativize_path,
    ensure_abs,
    strip_before_start_root,
    validate,
)


class GitleaksLeak(BaseModel):
    """Pydantic model for a single Gitleaks finding."""
    Description: Optional[str] = None
    StartLine: Optional[int] = None
    EndLine: Optional[int] = None
    StartColumn: Optional[int] = None
    EndColumn: Optional[int] = None
    Match: Optional[str] = None
    Secret: Optional[str] = None
    File: str
    SymlinkFile: Optional[str] = None
    Commit: Optional[str] = None
    Entropy: Optional[float] = None
    Author: Optional[str] = None
    Email: Optional[str] = None
    Date: Optional[str] = None
    Message: Optional[str] = None
    Tags: Optional[List[str]] = None
    RuleID: Optional[str] = Field(None, alias="RuleID")
    Fingerprint: Optional[str] = None
    
    model_config = ConfigDict(
        extra="allow",
        populate_by_name=True
    )


def gitleaks_json_to_models(
    raw: Union[dict, list],
    generated_at: Optional[str] = None,
    *,
    cwd: Optional[str] = None,
    start_root: Optional[str] = None,
    redacted: bool = True,
) -> Tuple["ScanMetadata", List["GitleaksResult"]]:
    """
    Convert Gitleaks JSON output to ORM models.
    
    Parameters
    ----------
    raw : dict or list
        Raw JSON output from Gitleaks. Can be either:
        - Complete output list of findings
        - Wrapped dict with 'results' or 'leaks' key
    generated_at : str, optional
        ISO timestamp for the scan. Defaults to current time.
    cwd : str, optional
        Working directory for path resolution.
    start_root : str, optional
        Project root for relative paths.
    redacted : bool, optional
        Whether secrets are redacted (default: True for safety)
    
    Returns
    -------
    tuple of (ScanMetadata, List[GitleaksResult])
        Scan metadata and list of secret findings.
    
    Examples
    --------
    >>> raw = [{"File": "config.py", "RuleID": "api-key", "StartLine": 5}]
    >>> scan, rows = gitleaks_json_to_models(raw, cwd="/project")
    >>> len(rows)
    1
    """
    # Handle both list and dict inputs
    if isinstance(raw, list):
        leaks = [validate(GitleaksLeak, item) for item in raw]
    elif isinstance(raw, dict):
        # Handle wrapped formats
        leak_data = raw.get("results") or raw.get("leaks") or raw.get("findings") or []
        leaks = [validate(GitleaksLeak, item) for item in leak_data]
    else:
        raise TypeError(f"Unsupported input type: {type(raw)!r}")
    
    # Create scan metadata
    scan_row = ScanMetadata(scan_timestamp=generated_at or now_iso())
    
    # Collect file paths for root determination
    file_paths = [leak.File for leak in leaks if leak.File]
    rel_paths: List[str] = [
        relativize_path(f, cwd) or f for f in file_paths
    ]
    root_label = determine_root_label(cwd, rel_paths)
    
    # Convert each leak to ORM model
    rows: List[GitleaksResult] = []
    for leak in leaks:
        # Resolve absolute path
        abs_path = ensure_abs(leak.File, cwd)
        abs_path = strip_before_start_root(abs_path, start_root)
        
        # Handle secret redaction
        secret_value = leak.Secret if not redacted else "REDACTED"
        match_value = leak.Match if not redacted else (leak.Match if leak.Match and "REDACTED" in leak.Match else "REDACTED")
        
        rows.append(
            GitleaksResult(
                scan=scan_row,
                file_path=abs_path,
                root=start_root or root_label,
                line_number=leak.StartLine,
                end_line_number=leak.EndLine or leak.StartLine,
                col_offset=leak.StartColumn,
                end_col_offset=leak.EndColumn,
                rule_id=leak.RuleID,
                description=leak.Description,
                fingerprint=leak.Fingerprint,
                secret=secret_value,
                match=match_value,
                entropy=leak.Entropy,
                commit=leak.Commit if leak.Commit else None,
                author=leak.Author if leak.Author else None,
                email=leak.Email if leak.Email else None,
                date=leak.Date if leak.Date else None,
                message=leak.Message if leak.Message else None,
                tags=leak.Tags if leak.Tags else None,
                symlink_file=leak.SymlinkFile if leak.SymlinkFile else None,
            )
        )
    
    return scan_row, rows


__all__ = [
    "GitleaksLeak",
    "gitleaks_json_to_models",
]
