# Copyright (c) 2025 Anush Krishna
# Licensed under the MIT License. See LICENSE file in the project root.

"""SQLAlchemy ORM models for database schema.

This module defines the database schema using SQLAlchemy ORM models for
storing static analysis results from multiple tools including Bandit, Mypy,
Radon, Vulture, ESLint, and Semgrep.

All result models inherit from ResultsBase which provides common fields and
automatic primary key generation.

Classes
-------
Base : SQLAlchemy declarative base
ResultsBase : Base class for all result models
ScanMetadata : Scan metadata and configuration
BanditResult : Bandit security analysis results
MypyResult : Mypy type checking results
EslintResult : ESLint linting results
SemgrepResult : Semgrep pattern matching results
RadonResult : Radon code metrics results
VultureResult : Vulture dead code detection results

Examples
--------
Create a scan with results:
    >>> from auditor.core.models.orm import BanditResult, ScanMetadata
    >>> scan = ScanMetadata(scan_timestamp='2025-01-01T00:00:00')
    >>> result = BanditResult(
    ...     scan=scan,
    ...     file_path='test.py',
    ...     line_number=10,
    ...     message='Security issue detected'
    ... )

See Also
--------
auditor.infra.db : Database utilities
auditor.core.models.schema : Pydantic models
"""
from __future__ import annotations

import hashlib
import os
from sqlalchemy import (
    Column,
    Integer,
    String,
    ForeignKey,
    Text,
    Float,
    JSON,
    Boolean,
    Index,
)
from sqlalchemy import event

from sqlalchemy.orm import relationship, declarative_base, declared_attr


Base = declarative_base()


class ScanMetadata(Base):
    """
    Metadata for each audit scan.
    
    Each scan represents a single execution of the static analysis tools.
    Related results from all tools are linked via the scan_id foreign key.
    
    Attributes:
        id: Auto-incrementing primary key
        scan_timestamp: ISO format timestamp of when the scan was run
    """
    __tablename__ = "scan_metadata"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_timestamp = Column(String, nullable=False)

    bandit_results = relationship(
        "BanditResult", back_populates="scan", cascade="all, delete-orphan"
    )
    mypy_results = relationship(
        "MypyResult", back_populates="scan", cascade="all, delete-orphan"
    )
    radon_results = relationship(
        "RadonResult", back_populates="scan", cascade="all, delete-orphan"
    )
    vulture_results = relationship(
        "VultureResult", back_populates="scan", cascade="all, delete-orphan"
    )
    eslint_results = relationship(
        "EslintResult", back_populates="scan", cascade="all, delete-orphan"
    )
    semgrep_results = relationship(
        "SemgrepResult", back_populates="scan", cascade="all, delete-orphan"
    )
    gitleaks_results = relationship(
        "GitleaksResult", back_populates="scan", cascade="all, delete-orphan"
    )
    biome_results = relationship(
        "BiomeResult", back_populates="scan", cascade="all, delete-orphan"
    )
    snyk_results = relationship(
        "SnykResult", back_populates="scan", cascade="all, delete-orphan"
    )
    bearer_results = relationship(
        "BearerResult", back_populates="scan", cascade="all, delete-orphan"
    )
    qlty_results = relationship(
        "QltyResult", back_populates="scan", cascade="all, delete-orphan"
    )


class ResultsBase(Base):
    """
    Abstract base class for all tool result models.
    
    Provides common fields shared across all static analysis tools:
    - Location information (file, line, column)
    - Automatic primary key generation based on content
    - Relationship to scan metadata
    
    The primary key is automatically generated as a SHA-256 hash of:
    - Table name
    - Project root
    - Relative file path
    - Tool-specific identifying fields (fingerprint, rule_id, message, etc.)
    - Location information
    
    This ensures duplicate detection while allowing re-scanning of the same code.
    
    Attributes:
        pk: SHA-256 hash used as primary key (64 hex characters)
        scan_id: Foreign key to scan_metadata table
        file_path: Full or relative path to the file
        root: Project root directory
        line_number: Starting line number of the issue
        end_line_number: Ending line number of the issue
        col_offset: Starting column offset
        end_col_offset: Ending column offset
    """
    __abstract__ = True

    pk = Column(String(64), primary_key=True)  # sha256 hex
    
    @declared_attr
    def scan_id(cls):
        return Column(Integer, ForeignKey("scan_metadata.id"), nullable=False)

    file_path       = Column(String, nullable=True, default="")
    root            = Column(String, nullable=True, default="")
    line_number     = Column(Integer, nullable=True, default=None)
    end_line_number = Column(Integer, nullable=True, default=None)
    col_offset      = Column(Integer, nullable=True, default=None)
    end_col_offset  = Column(Integer, nullable=True, default=None)

    # @declared_attr
    # def __table_args__(cls):
    #     # one set of indexes per concrete subclass with unique names
    #     return (
    #         Index(f"ix_{cls.__tablename__}_scan_id", "scan_id"),
    #         Index(f"ix_{cls.__tablename__}_file_path", "file_path"),
    #     )

    # ---------- PK builder ----------
    def build_pk(self) -> str:
        import hashlib, os
        table = type(self).__tablename__
        rel_or_file = getattr(self, "relpath", None) or (self.file_path or "")
        root = (self.root or "")
        # normalize
        root = root.replace("\\", "/")
        try:
            # only relativize absolute paths; otherwise keep original rel path
            rel = os.path.relpath(rel_or_file, root) if (root and os.path.isabs(rel_or_file)) else rel_or_file
        except Exception:
            rel = rel_or_file
        rel = rel.replace("\\", "/")

        # --- include root explicitly to make PK project-root aware ---
        parts = [table, root, rel]

        cols = ["fingerprint", "row_type", "metric_type", "rule_id", "check_id", "message", "line_number", "end_line_number", "col_offset", "end_col_offset"]

        for attr in cols:
            val = getattr(self, attr, None)
            if val:
                parts.append(str(val))

        key = "|".join(parts)
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

@event.listens_for(ResultsBase, "before_insert", propagate=True)
def _resultsbase_set_pk_before_insert(mapper, connection, target):
    # Compute PK just-in-time if missing
    if not getattr(target, "pk", None):
        target.pk = target.build_pk()

@event.listens_for(ResultsBase, "before_update", propagate=True)
def _resultsbase_set_pk_before_update(mapper, connection, target):
    # Safety: if an update clears pk somehow, recompute it
    if not getattr(target, "pk", None):
        target.pk = target.build_pk()

class BanditResult(ResultsBase):
    __tablename__ = "bandit_results"

    code = Column(Text, nullable=True)
    issue_confidence = Column(String, nullable=True)
    message = Column(Text, nullable=True)
    rule = Column(String, nullable=True)

    scan = relationship("ScanMetadata", back_populates="bandit_results")

class MypyResult(ResultsBase):
    __tablename__ = "mypy_results"

    message  = Column(Text,   nullable=False)
    hint     = Column(Text,   nullable=True)
    code     = Column(String, nullable=True)   # e.g. "no-untyped-def", "misc"
    severity = Column(String, nullable=True)   # e.g. "error", "note", "warning"

    scan = relationship("ScanMetadata", back_populates="mypy_results")



class RadonResult(ResultsBase):
    __tablename__ = "radon_results"

    metric_type = Column(String, nullable=False)

    cc_blocks = Column(Integer, nullable=True)
    cc_total = Column(Float, nullable=True)
    cc_max = Column(Float, nullable=True)
    cc_avg = Column(Float, nullable=True)
    cc_worst_rank = Column(String, nullable=True)
    cc_rank_counts = Column(JSON, nullable=True)

    mi = Column(Float, nullable=True)
    mi_rank = Column(String, nullable=True)

    raw_loc = Column(Integer, nullable=True)
    raw_sloc = Column(Integer, nullable=True)
    raw_lloc = Column(Integer, nullable=True)
    raw_comments = Column(Integer, nullable=True)
    raw_multi = Column(Integer, nullable=True)
    raw_blank = Column(Integer, nullable=True)
    raw_single_comments = Column(Integer, nullable=True)

    hal_volume = Column(Float, nullable=True)
    hal_difficulty = Column(Float, nullable=True)
    hal_effort = Column(Float, nullable=True)
    hal_time = Column(Float, nullable=True)
    hal_bugs = Column(Float, nullable=True)

    extra = Column(JSON, nullable=True)

    scan = relationship("ScanMetadata", back_populates="radon_results")


class VultureResult(ResultsBase):
    __tablename__ = "vulture_results"

    message = Column(Text, nullable=False)
    confidence = Column(Integer, nullable=True)
    kind = Column(String, nullable=True)

    scan = relationship("ScanMetadata", back_populates="vulture_results")


class EslintResult(ResultsBase):
    __tablename__ = "eslint_results"


    # What kind of row is this?
    # "scan" (summary), "file" (per-file tallies), "issue" (each ESLint message)
    row_type = Column(String, nullable=False)
    tool = Column(String, nullable=True, default="eslint")


    # Issue-level data
    rule_id = Column(String, nullable=True)    # e.g. "@typescript-eslint/no-unused-vars"
    severity = Column(Integer, nullable=True)  # 1=warning, 2=error
    message = Column(Text, nullable=True)
    fatal = Column(Boolean, nullable=True)
    fix = Column(Boolean, nullable=True)       # has a fix object?

    # Extra details (issue)
    node_type = Column(String, nullable=True)  # message["nodeType"]
    message_id = Column(String, nullable=True) # message["messageId"]

    suggestion_count = Column(Integer, nullable=True)
    suggestions = Column(JSON, nullable=True)  # raw suggestions (sanitized)
    fix_text = Column(Text, nullable=True)     # message["fix"]["text"]
    fix_range = Column(JSON, nullable=True)    # message["fix"]["range"] -> [start,end]


    scan = relationship("ScanMetadata", back_populates="eslint_results")

class SemgrepResult(ResultsBase):
    __tablename__ = "semgrep_results"

    row_type = Column(String, nullable=False)
    tool = Column(String, nullable=True, default="semgrep")

    rule_id = Column(String, nullable=True)
    check_id = Column(String, nullable=True)
    severity_text = Column(String, nullable=True)
    message = Column(Text, nullable=True)
    fix = Column(Text, nullable=True)
    fingerprint = Column(String, nullable=True)
    engine_kind = Column(String, nullable=True)
    validation = Column(String, nullable=True)

    category = Column(String, nullable=True)
    subcategory = Column(JSON, nullable=True)
    technology = Column(JSON, nullable=True)
    cwe = Column(JSON, nullable=True)
    owasp = Column(JSON, nullable=True)
    references = Column(JSON, nullable=True)
    likelihood = Column(String, nullable=True)
    impact = Column(String, nullable=True)
    confidence_text = Column(String, nullable=True)
    vulnerability_class = Column(JSON, nullable=True)
    source_url = Column(String, nullable=True)
    shortlink = Column(String, nullable=True)
    metadata_blob = Column("metadata", JSON, nullable=True)

    file_path = Column(String, nullable=True)
    root = Column(String, nullable=True)
    line_number = Column(Integer, nullable=True)
    end_line_number = Column(Integer, nullable=True)

    scan = relationship("ScanMetadata", back_populates="semgrep_results")


class GitleaksResult(ResultsBase):
    """Results from Gitleaks secret scanning.
    
    Gitleaks detects hardcoded secrets like passwords, API keys,
    and tokens in source code.
    """
    __tablename__ = "gitleaks_results"
    
    # Core identification
    rule_id = Column(String, nullable=True)           # e.g., "aws-access-token"
    description = Column(Text, nullable=True)         # Human-readable description
    fingerprint = Column(String, nullable=True)       # Unique identifier for the finding
    
    # Secret details
    secret = Column(Text, nullable=True)              # The actual secret (redactable)
    match = Column(Text, nullable=True)               # The matched string
    entropy = Column(Float, nullable=True)            # Entropy score
    
    # Git metadata (if scanning git repo)
    commit = Column(String, nullable=True)            # Commit hash
    author = Column(String, nullable=True)            # Commit author
    email = Column(String, nullable=True)             # Author email
    date = Column(String, nullable=True)              # Commit date
    message = Column(Text, nullable=True)             # Commit message
    
    # Additional fields
    tags = Column(JSON, nullable=True)                # Rule tags
    symlink_file = Column(String, nullable=True)      # If file is a symlink
    
    scan = relationship("ScanMetadata", back_populates="gitleaks_results")


class BiomeResult(ResultsBase):
    """Results from Biome linter/formatter analysis.
    
    Biome is a fast linter and formatter for JavaScript, TypeScript, JSX, and TSX.
    It provides comprehensive diagnostics with detailed location and fix information.
    """
    __tablename__ = "biome_results"
    
    # Core identification
    category = Column(String, nullable=True)           # e.g., "lint/correctness/noUnusedVariables"
    severity = Column(String, nullable=True)           # "error", "warning", "info"
    description = Column(Text, nullable=True)          # Short description
    message = Column(Text, nullable=True)              # Full formatted message
    
    # Location details (span is byte offsets in the file)
    span_start = Column(Integer, nullable=True)        # Start byte offset
    span_end = Column(Integer, nullable=True)          # End byte offset
    
    # Fix information
    fixable = Column(Boolean, nullable=True)           # Whether diagnostic has a suggested fix
    
    # Additional metadata
    tags = Column(JSON, nullable=True)                 # Tags like ["fixable"]
    advices = Column(JSON, nullable=True)              # Advice messages
    
    scan = relationship("ScanMetadata", back_populates="biome_results")


class SnykResult(ResultsBase):
    """Results from Snyk Code SAST analysis.
    
    Snyk Code is a static application security testing (SAST) tool that detects
    security vulnerabilities and code quality issues. It outputs SARIF format.
    """
    __tablename__ = "snyk_results"
    
    # Core identification
    rule_id = Column(String, nullable=True)            # e.g., "javascript/DOMXSS"
    rule_name = Column(String, nullable=True)          # e.g., "DOMXSS"
    fingerprint = Column(String, nullable=True)        # Unique identifier for the finding
    
    # Severity and classification
    level = Column(String, nullable=True)              # "warning", "error", "note"
    severity = Column(String, nullable=True)           # Alternative severity field
    message = Column(Text, nullable=True)              # Issue description
    message_markdown = Column(Text, nullable=True)     # Formatted markdown message
    
    # Security metadata
    cwe = Column(JSON, nullable=True)                  # CWE identifiers
    categories = Column(JSON, nullable=True)           # e.g., ["Security"]
    tags = Column(JSON, nullable=True)                 # Rule tags
    
    # Priority scoring
    priority_score = Column(Integer, nullable=True)    # Snyk's priority score
    priority_factors = Column(JSON, nullable=True)     # Factors affecting priority
    
    # Fix information
    is_autofixable = Column(Boolean, nullable=True)    # Whether auto-fix is available
    precision = Column(String, nullable=True)          # "very-high", "high", "medium", "low"
    
    # Data flow (for taint analysis)
    code_flows = Column(JSON, nullable=True)           # Data flow paths
    
    # Additional metadata
    help_text = Column(Text, nullable=True)            # Detailed help text
    help_markdown = Column(Text, nullable=True)        # Markdown formatted help
    example_fixes = Column(JSON, nullable=True)        # Example commit fixes
    
    scan = relationship("ScanMetadata", back_populates="snyk_results")


class BearerResult(ResultsBase):
    """Results from Bearer SAST analysis.
    
    Bearer is a code security and privacy scanner that focuses on detecting
    sensitive data flows and security vulnerabilities.
    """
    __tablename__ = "bearer_results"
    
    # Core identification
    rule_id = Column(String, nullable=True)            # e.g., "javascript_lang_logger"
    title = Column(String, nullable=True)              # Issue title
    fingerprint = Column(String, nullable=True)        # Unique identifier
    old_fingerprint = Column(String, nullable=True)    # Legacy identifier
    
    # Severity and classification
    severity = Column(String, nullable=True)           # "high", "medium", "low", "critical"
    description = Column(Text, nullable=True)          # Full description with remediations
    message = Column(Text, nullable=True)              # Short message
    
    # Security metadata
    cwe_ids = Column(JSON, nullable=True)              # CWE identifiers (e.g., ["73", "22"])
    category_groups = Column(JSON, nullable=True)      # e.g., ["PII", "Personal Data"]
    
    # Data type information (for data leakage rules)
    data_type = Column(JSON, nullable=True)            # Data type details (category, name)
    
    # Location details (source and sink for data flow)
    source = Column(JSON, nullable=True)               # Source location of data
    sink = Column(JSON, nullable=True)                 # Sink location where data flows
    parent_line_number = Column(Integer, nullable=True) # Parent line for context
    
    # Code context
    code_extract = Column(Text, nullable=True)         # Code snippet
    filename_relative = Column(String, nullable=True)  # Relative filename
    
    # Documentation
    documentation_url = Column(String, nullable=True)  # Rule documentation URL
    
    scan = relationship("ScanMetadata", back_populates="bearer_results")


class QltyResult(ResultsBase):
    """Results from Qlty code quality analysis.
    
    Qlty is a unified code quality platform that runs multiple linters
    and formatters. It outputs results in SARIF format.
    """
    __tablename__ = "qlty_results"
    
    # Core identification
    rule_id = Column(String, nullable=True)            # e.g., "ripgrep:TODO"
    rule_name = Column(String, nullable=True)          # Rule name if available
    
    # Severity and classification
    level = Column(String, nullable=True)              # "error", "warning", "note"
    message = Column(Text, nullable=True)              # Issue message
    
    # Taxa/categories (Qlty-specific)
    taxa = Column(JSON, nullable=True)                 # e.g., [{"id": "lint", "name": "lint"}]
    
    # Tool information
    tool_name = Column(String, nullable=True)          # Underlying tool (e.g., "ripgrep", "eslint")
    tool_version = Column(String, nullable=True)       # Qlty version
    
    # Additional metadata
    properties = Column(JSON, nullable=True)           # Additional properties
    
    scan = relationship("ScanMetadata", back_populates="qlty_results")


