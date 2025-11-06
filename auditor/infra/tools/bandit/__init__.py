from __future__ import annotations

"""Bandit security analysis tool wrapper.

Bandit is a tool designed to find common security issues in Python code.

Classes
-------
BanditTool : Bandit tool wrapper

Examples
--------
>>> from auditor.infra.tools.bandit import BanditTool
>>> tool = BanditTool()
>>> result = tool.audit("file.py")

See Also
--------
auditor.core.models.parsers.bandit : Bandit parser
"""

from .base import BanditTool

__all__ = ["BanditTool"]
