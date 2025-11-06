"""Main entry point for running auditor as a module.

This module enables running auditor via `python -m auditor`.

Examples
--------
$ python -m auditor --help
$ python -m auditor audit /path/to/project

See Also
--------
auditor.auditor_cli.cli : CLI implementation
"""
from __future__ import annotations

from .main import main


if __name__ == "__main__":
    main()
