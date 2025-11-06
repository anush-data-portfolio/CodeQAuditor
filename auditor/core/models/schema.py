"""Pydantic schema models for data validation.

This module defines Pydantic models used for data validation and serialization
throughout the application.

Classes
-------
ToolRunResult : Tool execution result
AuditResults : Standardized audit finding

Examples
--------
>>> result = AuditResults(
...     tool="bandit",
...     message="Security issue",
...     file_path="test.py",
...     start_line=10
... )

See Also
--------
auditor.core.models.orm : Database ORM models
"""
from __future__ import annotations

from .parsers.bandit import (
    BanditResultModel,
    BanditScan,
    IssueCWE,
    bandit_json_to_models,
)
from .parsers.mypy import MypyItem, mypy_ndjson_to_models, parse_mypy_ndjson
from .parsers.radon import radon_to_models
from .parsers.vulture import vulture_text_to_models
from .parsers.common import ToolRunResult, AuditResults
from .parsers.eslint import eslint_rows_to_models
from .parsers.semgrep import semgrep_to_models
from .parsers.gitleaks import GitleaksLeak, gitleaks_json_to_models
from .parsers.biome import BiomeDiagnostic, BiomeOutput, biome_json_to_models
from .parsers.snyk import snyk_sarif_to_models
from .parsers.bearer import bearer_json_to_models
from .parsers.qlty import qlty_sarif_to_models


__all__ = [
    "IssueCWE",
    "BanditResultModel",
    "BanditScan",
    "bandit_json_to_models",
    "MypyItem",
    "parse_mypy_ndjson",
    "mypy_ndjson_to_models",
    "radon_to_models",
    "vulture_text_to_models",
    "eslint_rows_to_models",
    "ToolRunResult",
    "AuditResults",
    "semgrep_to_models",
    "GitleaksLeak",
    "gitleaks_json_to_models",
    "BiomeDiagnostic",
    "BiomeOutput",
    "biome_json_to_models",
    "snyk_sarif_to_models",
    "bearer_json_to_models",
    "qlty_sarif_to_models",
]
