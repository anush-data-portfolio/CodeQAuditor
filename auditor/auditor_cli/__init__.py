from __future__ import annotations

"""Command-line interface for CodeQAuditor.

This package provides the CLI application built with Typer.

Modules
-------
cli : Main CLI implementation

Examples
--------
Run from command line:
    $ python -m auditor audit /path/to/project

See Also
--------
auditor.application : Application logic
"""

from .cli import app

__all__ = ["app"]
