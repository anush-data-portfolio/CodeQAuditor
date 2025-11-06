from __future__ import annotations

"""Vulture dead code detector tool wrapper.

Vulture finds unused code in Python programs.

Classes
-------
VultureTool : Vulture tool wrapper

Examples
--------
>>> from auditor.infra.tools.vulture import VultureTool
>>> tool = VultureTool()
>>> result = tool.audit("file.py")

See Also
--------
auditor.core.models.parsers.vulture : Vulture parser
"""

from .base import VultureTool

__all__ = ["VultureTool"]
