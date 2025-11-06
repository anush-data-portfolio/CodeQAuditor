"""Application layer for CodeQAuditor.

This package contains the application orchestration logic, including file discovery,
analysis coordination, and results extraction.
"""
from __future__ import annotations

from .extractor import extract_findings_to_json, metabob_to_auditor
from .file import discover_files
from .orchestrator import audit_file, available_tools, run_tool_direct

__all__ = [
    "extract_findings_to_json",
    "metabob_to_auditor",
    "discover_files",
    "audit_file",
    "available_tools",
    "run_tool_direct",
]
