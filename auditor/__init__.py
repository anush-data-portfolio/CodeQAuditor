"""CodeQAuditor - Multi-tool static analysis orchestration platform.

CodeQAuditor is a comprehensive static analysis orchestration tool that integrates
multiple analysis tools (Bandit, Mypy, ESLint, Semgrep, Radon, Vulture) into a
unified workflow with centralized result storage and reporting.

The package provides:
- Unified CLI for running multiple static analysis tools
- Database-backed result storage and retrieval
- Tool output parsing and normalization
- Parallel execution support
- JSON export capabilities

Examples
--------
Run analysis from command line:
    $ python -m auditor audit /path/to/project --tool bandit mypy

Export findings:
    $ python -m auditor export --output-path ./results

See Also
--------
auditor.auditor_cli.cli : Command-line interface
auditor.application : Application orchestration layer
auditor.core : Core domain models and exceptions
"""
from __future__ import annotations

__version__ = "1.0.0"
__author__ = "Anush Krishna"
__license__ = "MIT"

__all__ = ["__version__", "__author__", "__license__"]
