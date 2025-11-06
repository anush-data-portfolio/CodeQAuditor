"""
CodeQAuditor main entry point.

This module serves as the main entry point for the CodeQAuditor CLI application.
It delegates to the CLI module for actual command handling.
"""
from __future__ import annotations

from .auditor_cli.cli import app


def main() -> None:
    """
    Main entry point for CodeQAuditor application.
    
    Initializes and runs the CLI application.
    """
    app()


if __name__ == "__main__":
    main()
