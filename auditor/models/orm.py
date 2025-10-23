# orm.py
from __future__ import annotations

from sqlalchemy import Column, Integer, String, ForeignKey, Text, Float, JSON, Boolean
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()


class ScanMetadata(Base):
    __tablename__ = "scan_metadata"

    id = Column(Integer, primary_key=True)
    # ISO-8601 string like "2025-10-22T17:35:49Z"
    scan_timestamp = Column(String, nullable=False)

    # One-to-manys to concrete result tables
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


class ResultsBase(Base):
    __abstract__ = True

    id = Column(Integer, primary_key=True)

    scan_id = Column(Integer, ForeignKey("scan_metadata.id"), nullable=False)
    # IMPORTANT: no relationship() on abstract base; keep it on subclasses

    file_path = Column(String, nullable=False)
    root = Column(String, nullable=False)
    line_number = Column(Integer, nullable=True)
    end_line_number = Column(Integer, nullable=True)
    col_offset = Column(Integer, nullable=True)
    end_col_offset = Column(Integer, nullable=True)


class BanditResult(ResultsBase):
    __tablename__ = "bandit_results"

    # Bandit-specific fields
    code = Column(Text, nullable=True)  # Text in case snippets are large
    issue_confidence = Column(String, nullable=True)
    issue = Column(Text, nullable=True)
    rule = Column(String, nullable=True)

    # Relationship lives here (concrete class), paired with ScanMetadata.bandit_results
    scan = relationship("ScanMetadata", back_populates="bandit_results")


class MypyResult(ResultsBase):
    __tablename__ = "mypy_results"

    # mypy/pyright-like diagnostics
    message = Column(Text, nullable=False)
    hint = Column(Text, nullable=True)
    code = Column(String, nullable=True)
    severity = Column(String, nullable=True)

    # Relationship lives here, paired with ScanMetadata.mypy_results
    scan = relationship("ScanMetadata", back_populates="mypy_results")


class RadonResult(ResultsBase):
    __tablename__ = "radon_results"

    # 'cc' | 'mi' | 'raw' | 'hal'
    metric_type = Column(String, nullable=False)

    # ---- CC (Cyclomatic Complexity) aggregates ----
    cc_blocks = Column(Integer, nullable=True)
    cc_total = Column(Float, nullable=True)
    cc_max = Column(Float, nullable=True)
    cc_avg = Column(Float, nullable=True)
    cc_worst_rank = Column(String, nullable=True)
    cc_rank_counts = Column(JSON, nullable=True)  # {"A":8,"B":11,...}

    # ---- MI (Maintainability Index) ----
    mi = Column(Float, nullable=True)
    mi_rank = Column(String, nullable=True)  # A/B/C

    # ---- RAW metrics ----
    raw_loc = Column(Integer, nullable=True)
    raw_sloc = Column(Integer, nullable=True)
    raw_lloc = Column(Integer, nullable=True)
    raw_comments = Column(Integer, nullable=True)
    raw_multi = Column(Integer, nullable=True)
    raw_blank = Column(Integer, nullable=True)
    raw_single_comments = Column(Integer, nullable=True)

    # ---- Halstead (from total) ----
    hal_volume = Column(Float, nullable=True)
    hal_difficulty = Column(Float, nullable=True)
    hal_effort = Column(Float, nullable=True)
    hal_time = Column(Float, nullable=True)
    hal_bugs = Column(Float, nullable=True)

    # Extra details (e.g., halstead per-function dict, raw totals, cmd, etc.)
    extra = Column(JSON, nullable=True)

    scan = relationship("ScanMetadata", back_populates="radon_results")


class VultureResult(ResultsBase):
    __tablename__ = "vulture_results"

    message = Column(Text, nullable=False)
    confidence = Column(Integer, nullable=True)  # percentage 0-100
    kind = Column(String, nullable=True)

    scan = relationship("ScanMetadata", back_populates="vulture_results")


class EslintResult(ResultsBase):
    __tablename__ = "eslint_results"

    # 'scan' | 'file' | 'issue'
    row_type = Column(String, nullable=False)

    # Common
    tool = Column(String, nullable=True)  # 'eslint'
    relpath = Column(String, nullable=True)

    # Counts (used by 'scan' and 'file')
    error_count = Column(Integer, nullable=True)
    warning_count = Column(Integer, nullable=True)
    fixable_error_count = Column(Integer, nullable=True)
    fixable_warning_count = Column(Integer, nullable=True)

    # 'scan' extras
    file_count = Column(Integer, nullable=True)
    duration_s = Column(Float, nullable=True)
    cmd = Column(JSON, nullable=True)  # list[str]
    cwd = Column(String, nullable=True)
    returncode = Column(Integer, nullable=True)
    rule_counts = Column(JSON, nullable=True)  # {ruleId: count}

    # Scan-level complexity summaries (ESLint rules + optional Radon aggregates)
    complexity_count = Column(Integer, nullable=True)
    complexity_max = Column(Float, nullable=True)
    max_depth_count = Column(Integer, nullable=True)
    max_depth_max = Column(Float, nullable=True)
    max_params_count = Column(Integer, nullable=True)
    max_params_max = Column(Float, nullable=True)
    max_lines_func_count = Column(Integer, nullable=True)
    max_lines_func_max = Column(Float, nullable=True)
    import_cycle_count = Column(Integer, nullable=True)

    mi_min = Column(Float, nullable=True)
    mi_max = Column(Float, nullable=True)
    mi_avg = Column(Float, nullable=True)
    hal_volume_total = Column(Float, nullable=True)
    hal_effort_total = Column(Float, nullable=True)
    hal_bugs_total = Column(Float, nullable=True)

    # 'issue' fields
    rule_id = Column(String, nullable=True)
    severity = Column(Integer, nullable=True)  # 1=warning, 2=error
    message = Column(Text, nullable=True)
    fatal = Column(Boolean, nullable=True)
    fix = Column(Boolean, nullable=True)  # True if a fix object was present

    scan = relationship("ScanMetadata", back_populates="eslint_results")
