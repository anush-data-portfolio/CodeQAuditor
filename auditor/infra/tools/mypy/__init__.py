from __future__ import annotations

"""Mypy static type checker tool wrapper.

Mypy is a static type checker for Python that helps catch type errors.

Classes
-------
MypyTool : Mypy tool wrapper

Examples
--------
>>> from auditor.infra.tools.mypy import MypyTool
>>> tool = MypyTool()
>>> result = tool.audit("file.py")

See Also
--------
auditor.core.models.parsers.mypy : Mypy parser
"""

from .base import MypyTool

__all__ = ["MypyTool"]
