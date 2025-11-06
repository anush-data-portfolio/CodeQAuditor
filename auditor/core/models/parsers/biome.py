"""Parser for Biome JavaScript/TypeScript linter results.

Biome is a fast linter and formatter for JavaScript, TypeScript, JSX, and TSX.
This parser converts Biome's JSON output format into database models.

Functions
---------
biome_json_to_models : Parse Biome JSON output to ORM models

Examples
--------
>>> result = {"diagnostics": [{"category": "lint/..."}]}
>>> scan, rows = biome_json_to_models(result)

See Also
--------
auditor.infra.tools.biome : Biome tool wrapper
"""
from __future__ import annotations

from typing import Any, List, Optional, Tuple, Dict
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from ..orm import BiomeResult, ScanMetadata
from ._shared import (
    now_iso,
    determine_root_label,
    relativize_path,
    ensure_abs,
    strip_before_start_root,
    validate,
)


class BiomeLocation(BaseModel):
    """Location information in Biome output."""
    path: Optional[Dict[str, str]] = None
    span: Optional[List[int]] = None
    sourceCode: Optional[str] = None
    
    model_config = ConfigDict(extra="allow")


class BiomeDiagnostic(BaseModel):
    """Pydantic model for a single Biome diagnostic."""
    category: Optional[str] = None
    severity: Optional[str] = None
    description: Optional[str] = None
    message: Optional[Any] = None  # Can be list of formatted parts or string
    location: Optional[BiomeLocation] = None
    tags: Optional[List[str]] = None
    advices: Optional[Dict] = None
    verboseAdvices: Optional[Dict] = None
    source: Optional[str] = None
    
    model_config = ConfigDict(extra="allow")


class BiomeOutput(BaseModel):
    """Pydantic model for complete Biome output."""
    summary: Optional[Dict[str, Any]] = None
    diagnostics: List[BiomeDiagnostic] = []
    
    model_config = ConfigDict(extra="ignore")


def _extract_message_text(message: Any) -> str:
    """Extract plain text from Biome's message format.
    
    Biome messages can be:
    - A string
    - A list of message parts with content fields
    """
    if isinstance(message, str):
        return message
    elif isinstance(message, list):
        # Extract content from each part
        parts = []
        for part in message:
            if isinstance(part, dict) and "content" in part:
                parts.append(part["content"])
        return "".join(parts)
    return ""


def _parse_span_to_lines(source_code: Optional[str], span: Optional[List[int]]) -> Tuple[Optional[int], Optional[int]]:
    """Convert byte span to line numbers.
    
    Parameters
    ----------
    source_code : str, optional
        Full source code of the file
    span : List[int], optional
        [start_byte, end_byte] offsets
    
    Returns
    -------
    Tuple[Optional[int], Optional[int]]
        (start_line, end_line) with 1-based indexing
    """
    if not source_code or not span or len(span) < 2:
        return None, None
    
    try:
        start_byte, end_byte = span[0], span[1]
        # Count newlines before start_byte
        lines_before_start = source_code[:start_byte].count('\n')
        lines_before_end = source_code[:end_byte].count('\n')
        
        # Line numbers are 1-based
        start_line = lines_before_start + 1
        end_line = lines_before_end + 1
        
        return start_line, end_line
    except Exception:
        return None, None


def biome_json_to_models(
    raw: Dict[str, Any],
    generated_at: Optional[str] = None,
    *,
    cwd: Optional[str] = None,
    start_root: Optional[str] = None,
) -> Tuple[ScanMetadata, List[BiomeResult]]:
    """
    Convert Biome JSON output to ORM models.
    
    Parameters
    ----------
    raw : dict
        Raw JSON output from Biome with 'diagnostics' key
    generated_at : str, optional
        ISO timestamp for the scan. Defaults to current time.
    cwd : str, optional
        Working directory for path resolution.
    start_root : str, optional
        Project root for relative paths.
    
    Returns
    -------
    tuple of (ScanMetadata, List[BiomeResult])
        Scan metadata and list of result rows.
    
    Examples
    --------
    >>> raw = {"diagnostics": [{"category": "lint/...", "severity": "warning"}]}
    >>> scan, rows = biome_json_to_models(raw, cwd="/project")
    """
    # Validate input
    output = validate(BiomeOutput, raw)
    
    # Create scan metadata
    scan_row = ScanMetadata(scan_timestamp=generated_at or now_iso())
    
    # Collect relative paths for root determination
    rel_paths: List[str] = []
    for diag in output.diagnostics:
        if diag.location and diag.location.path:
            file_path = diag.location.path.get("file", "")
            if file_path:
                rel_paths.append(relativize_path(file_path, cwd) or file_path)
    
    root_label = determine_root_label(cwd, rel_paths)
    
    # Convert each diagnostic to ORM model
    rows: List[BiomeResult] = []
    for diag in output.diagnostics:
        if not diag.location or not diag.location.path:
            continue
        
        # Extract file path
        file_path_raw = diag.location.path.get("file", "")
        if not file_path_raw:
            continue
        
        # Resolve absolute path
        abs_path = ensure_abs(file_path_raw, cwd)
        abs_path = strip_before_start_root(abs_path, start_root)
        
        # Extract message text
        message_text = _extract_message_text(diag.message)
        
        # Parse span to line numbers
        source_code = diag.location.sourceCode
        span = diag.location.span
        line_start, line_end = _parse_span_to_lines(source_code, span)
        
        # Determine if fixable
        fixable = "fixable" in (diag.tags or [])
        
        # Create result row
        rows.append(
            BiomeResult(
                scan=scan_row,
                file_path=abs_path,
                root=start_root or root_label,
                line_number=line_start,
                end_line_number=line_end or line_start,
                col_offset=None,  # Biome uses byte spans, not column offsets
                end_col_offset=None,
                category=diag.category,
                severity=diag.severity,
                description=diag.description,
                message=message_text,
                span_start=span[0] if span and len(span) > 0 else None,
                span_end=span[1] if span and len(span) > 1 else None,
                fixable=fixable,
                tags=diag.tags,
                advices=diag.advices if isinstance(diag.advices, dict) else None,
            )
        )
    
    return scan_row, rows


__all__ = [
    "BiomeDiagnostic",
    "BiomeOutput",
    "biome_json_to_models",
]
