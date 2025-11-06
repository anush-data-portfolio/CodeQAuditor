"""Tool output parsers for static analysis results.

This package contains parsers for converting tool-specific output formats into
standardized database models. Each parser handles the unique output format of
its corresponding static analysis tool.

Supported Tools
---------------
- Bandit : Python security analyzer
- Mypy : Python static type checker  
- ESLint : JavaScript/TypeScript linter
- Semgrep : Multi-language pattern analyzer
- Radon : Python code metrics calculator
- Vulture : Python dead code detector

Parser Functions
----------------
Each tool has a dedicated parser function that converts tool output to ORM models:
- bandit_json_to_models : Parse Bandit JSON output
- mypy_ndjson_to_models : Parse Mypy newline-delimited JSON
- eslint_rows_to_models : Parse ESLint JSON output
- semgrep_to_models : Parse Semgrep JSON output
- radon_to_models : Parse Radon JSON metrics
- vulture_text_to_models : Parse Vulture text output

Examples
--------
Parse Bandit results:
    >>> from auditor.core.models.parsers import bandit_json_to_models
    >>> scan, rows = bandit_json_to_models(bandit_results, cwd="/path")
    >>> len(rows)
    5

See Also
--------
auditor.core.models.orm : ORM models for database storage
auditor.application.orchestrator : Tool execution orchestration
"""
from __future__ import annotations

from .bandit import bandit_json_to_models
from .mypy import mypy_ndjson_to_models, parse_mypy_ndjson
from .radon import radon_to_models
from .vulture import vulture_text_to_models
from .eslint import eslint_rows_to_models
from .semgrep import semgrep_to_models
from .common import ToolRunResult

__all__ = [
    "bandit_json_to_models",
    "mypy_ndjson_to_models",
    "parse_mypy_ndjson",
    "radon_to_models",
    "vulture_text_to_models",
    "eslint_rows_to_models",
    "semgrep_to_models",
    "ToolRunResult",
]
