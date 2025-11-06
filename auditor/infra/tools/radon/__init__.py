from __future__ import annotations

"""Radon code metrics tool wrapper.

Radon computes various metrics from Python source code including complexity.

Classes
-------
RadonTool : Radon tool wrapper

Examples
--------
>>> from auditor.infra.tools.radon import RadonTool
>>> tool = RadonTool()
>>> result = tool.audit("file.py")

See Also
--------
auditor.core.models.parsers.radon : Radon parser
"""

from .base import RadonTool

__all__ = ["RadonTool"]
