# Copyright (c) 2025 Anush Krishna
# Licensed under the MIT License. See LICENSE file in the project root.

from __future__ import annotations

"""Optimized database queries for common operations.

This module provides performance-optimized query functions for frequently
used database operations.

Functions
---------
get_findings_by_tool : Get findings filtered by tool
get_findings_by_severity : Get findings by severity level

Examples
--------
>>> from auditor.infra.db.optimized_queries import get_findings_by_tool
>>> findings = get_findings_by_tool(session, "bandit")

See Also
--------
auditor.infra.db.utils : Database utilities
"""

"""
Optimized database queries for common operations.

This module provides pre-optimized queries with proper indexing hints,
eager loading, and efficient filtering for common dashboard queries.
"""

from typing import List, Dict, Any, Optional
from sqlalchemy import func, select, and_, or_
from sqlalchemy.orm import Session, joinedload

from auditor.core.models.orm import (
    BanditResult,
    MypyResult,
    RadonResult,
    VultureResult,
    EslintResult,
    SemgrepResult,
    ScanMetadata
)
from auditor.core.logging_config import get_logger

logger = get_logger(__name__)


def get_latest_scan_id(session: Session) -> Optional[int]:
    """
    Get the ID of the most recent scan.
    
    Args:
        session: Database session
        
    Returns:
        Latest scan ID or None if no scans exist
    """
    result = session.query(
        func.max(ScanMetadata.id)
    ).scalar()
    return result


def get_issues_by_tool(session: Session, scan_id: int) -> Dict[str, int]:
    """
    Get issue counts grouped by tool.
    
    Optimized query that counts issues across all tool result tables.
    
    Args:
        session: Database session
        scan_id: Scan ID to query
        
    Returns:
        Dictionary mapping tool names to issue counts
    """
    counts = {}
    
    # Bandit
    counts['bandit'] = session.query(func.count(BanditResult.pk)).filter(
        BanditResult.scan_id == scan_id
    ).scalar() or 0
    
    # Mypy
    counts['mypy'] = session.query(func.count(MypyResult.pk)).filter(
        MypyResult.scan_id == scan_id
    ).scalar() or 0
    
    # Vulture
    counts['vulture'] = session.query(func.count(VultureResult.pk)).filter(
        VultureResult.scan_id == scan_id
    ).scalar() or 0
    
    # ESLint - only count issues, not summary rows
    counts['eslint'] = session.query(func.count(EslintResult.pk)).filter(
        and_(
            EslintResult.scan_id == scan_id,
            EslintResult.row_type == 'issue'
        )
    ).scalar() or 0
    
    # Semgrep - only count issues
    counts['semgrep'] = session.query(func.count(SemgrepResult.pk)).filter(
        and_(
            SemgrepResult.scan_id == scan_id,
            SemgrepResult.row_type == 'issue'
        )
    ).scalar() or 0
    
    # Radon - count files with metrics
    counts['radon'] = session.query(func.count(func.distinct(RadonResult.file_path))).filter(
        RadonResult.scan_id == scan_id
    ).scalar() or 0
    
    return counts


def get_issues_by_severity(session: Session, scan_id: int) -> Dict[str, int]:
    """
    Get issue counts grouped by severity.
    
    Normalizes severity levels across different tools.
    
    Args:
        session: Database session
        scan_id: Scan ID to query
        
    Returns:
        Dictionary mapping severity levels to counts
    """
    severity_counts = {'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    
    # Bandit - uses confidence levels
    bandit_high = session.query(func.count(BanditResult.pk)).filter(
        and_(
            BanditResult.scan_id == scan_id,
            BanditResult.issue_confidence == 'HIGH'
        )
    ).scalar() or 0
    
    bandit_med = session.query(func.count(BanditResult.pk)).filter(
        and_(
            BanditResult.scan_id == scan_id,
            BanditResult.issue_confidence == 'MEDIUM'
        )
    ).scalar() or 0
    
    bandit_low = session.query(func.count(BanditResult.pk)).filter(
        and_(
            BanditResult.scan_id == scan_id,
            BanditResult.issue_confidence == 'LOW'
        )
    ).scalar() or 0
    
    severity_counts['high'] += bandit_high
    severity_counts['medium'] += bandit_med
    severity_counts['low'] += bandit_low
    
    # Mypy - errors are high, warnings are medium
    mypy_errors = session.query(func.count(MypyResult.pk)).filter(
        and_(
            MypyResult.scan_id == scan_id,
            MypyResult.severity == 'error'
        )
    ).scalar() or 0
    
    mypy_warnings = session.query(func.count(MypyResult.pk)).filter(
        and_(
            MypyResult.scan_id == scan_id,
            MypyResult.severity.in_(['warning', 'note'])
        )
    ).scalar() or 0
    
    severity_counts['high'] += mypy_errors
    severity_counts['medium'] += mypy_warnings
    
    # ESLint - severity 2=error (high), 1=warning (medium)
    eslint_errors = session.query(func.count(EslintResult.pk)).filter(
        and_(
            EslintResult.scan_id == scan_id,
            EslintResult.row_type == 'issue',
            EslintResult.severity == 2
        )
    ).scalar() or 0
    
    eslint_warnings = session.query(func.count(EslintResult.pk)).filter(
        and_(
            EslintResult.scan_id == scan_id,
            EslintResult.row_type == 'issue',
            EslintResult.severity == 1
        )
    ).scalar() or 0
    
    severity_counts['high'] += eslint_errors
    severity_counts['medium'] += eslint_warnings
    
    # Semgrep
    semgrep_high = session.query(func.count(SemgrepResult.pk)).filter(
        and_(
            SemgrepResult.scan_id == scan_id,
            SemgrepResult.row_type == 'issue',
            SemgrepResult.severity_text.in_(['ERROR', 'HIGH'])
        )
    ).scalar() or 0
    
    semgrep_med = session.query(func.count(SemgrepResult.pk)).filter(
        and_(
            SemgrepResult.scan_id == scan_id,
            SemgrepResult.row_type == 'issue',
            SemgrepResult.severity_text.in_(['WARNING', 'MEDIUM'])
        )
    ).scalar() or 0
    
    semgrep_low = session.query(func.count(SemgrepResult.pk)).filter(
        and_(
            SemgrepResult.scan_id == scan_id,
            SemgrepResult.row_type == 'issue',
            SemgrepResult.severity_text.in_(['INFO', 'LOW'])
        )
    ).scalar() or 0
    
    severity_counts['high'] += semgrep_high
    severity_counts['medium'] += semgrep_med
    severity_counts['low'] += semgrep_low
    
    # Vulture - all considered low priority
    vulture_count = session.query(func.count(VultureResult.pk)).filter(
        VultureResult.scan_id == scan_id
    ).scalar() or 0
    
    severity_counts['info'] += vulture_count
    
    return severity_counts


def get_issues_by_file(
    session: Session,
    scan_id: int,
    file_path: Optional[str] = None,
    limit: int = 100
) -> List[Dict[str, Any]]:
    """
    Get issues for a specific file or all files.
    
    Args:
        session: Database session
        scan_id: Scan ID to query
        file_path: Optional file path filter
        limit: Maximum number of results
        
    Returns:
        List of issue dictionaries
    """
    issues = []
    
    # Collect from all tables
    tables = [
        (BanditResult, 'bandit'),
        (MypyResult, 'mypy'),
        (VultureResult, 'vulture'),
        (EslintResult, 'eslint'),
        (SemgrepResult, 'semgrep'),
    ]
    
    for model_class, tool_name in tables:
        query = session.query(model_class).filter(
            model_class.scan_id == scan_id
        )
        
        # Filter by file if specified
        if file_path:
            query = query.filter(model_class.file_path == file_path)
        
        # For ESLint and Semgrep, only get issues
        if tool_name in ['eslint', 'semgrep']:
            query = query.filter(model_class.row_type == 'issue')
        
        # Apply limit per table
        query = query.limit(limit)
        
        results = query.all()
        for result in results:
            issues.append({
                'tool': tool_name,
                'file_path': result.file_path,
                'line_number': result.line_number,
                'message': getattr(result, 'message', ''),
                'severity': _normalize_severity(result, tool_name),
            })
    
    return issues[:limit]


def get_file_paths(session: Session, scan_id: int) -> List[str]:
    """
    Get all unique file paths in the scan.
    
    Args:
        session: Database session
        scan_id: Scan ID to query
        
    Returns:
        Sorted list of unique file paths
    """
    paths = set()
    
    # Query each table
    for model_class in [BanditResult, MypyResult, VultureResult, EslintResult, SemgrepResult, RadonResult]:
        results = session.query(model_class.file_path).filter(
            and_(
                model_class.scan_id == scan_id,
                model_class.file_path.isnot(None)
            )
        ).distinct().all()
        
        paths.update(r[0] for r in results if r[0])
    
    return sorted(paths)


def _normalize_severity(result: Any, tool_name: str) -> str:
    """
    Normalize severity level across different tools.
    
    Args:
        result: ORM result object
        tool_name: Name of the tool
        
    Returns:
        Normalized severity string
    """
    if tool_name == 'bandit':
        confidence = getattr(result, 'issue_confidence', '').upper()
        if confidence == 'HIGH':
            return 'high'
        elif confidence == 'MEDIUM':
            return 'medium'
        else:
            return 'low'
    
    elif tool_name == 'mypy':
        severity = getattr(result, 'severity', '').lower()
        if severity == 'error':
            return 'high'
        elif severity == 'warning':
            return 'medium'
        else:
            return 'low'
    
    elif tool_name == 'eslint':
        severity_num = getattr(result, 'severity', 1)
        return 'high' if severity_num == 2 else 'medium'
    
    elif tool_name == 'semgrep':
        severity_text = getattr(result, 'severity_text', '').upper()
        if severity_text in ['ERROR', 'HIGH']:
            return 'high'
        elif severity_text in ['WARNING', 'MEDIUM']:
            return 'medium'
        else:
            return 'low'
    
    elif tool_name == 'vulture':
        return 'info'
    
    return 'low'
