from __future__ import annotations

"""Semgrep pattern matching tool wrapper.

Semgrep is a fast static analysis tool for finding bugs and enforcing standards.

Classes
-------
SemgrepTool : Semgrep tool wrapper

Examples
--------
>>> from auditor.infra.tools.semgrep import SemgrepTool
>>> tool = SemgrepTool()  
>>> result = tool.audit("file.py")

See Also
--------
auditor.core.models.parsers.semgrep : Semgrep parser
"""

