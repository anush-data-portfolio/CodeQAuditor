from __future__ import annotations

"""Static analysis tool wrapper implementations.

This package contains wrapper classes for all supported static analysis tools.
Each tool has its own subpackage with implementation and configuration.

Supported Tools
---------------
- Bandit : Python security analyzer
- Mypy : Python type checker
- ESLint : JavaScript/TypeScript linter  
- Semgrep : Multi-language pattern analyzer
- Radon : Python metrics calculator
- Vulture : Python dead code detector
- JSCPD : Copy-paste detector

Examples
--------
>>> from auditor.infra.tools.bandit import BanditTool
>>> tool = BanditTool()
>>> result = tool.audit("/path/to/file.py")

See Also
--------
auditor.infra.tools.base : Base tool classes
auditor.application.orchestrator : Tool orchestration
"""

from .base import AuditTool, CommandAuditTool


__all__ = [
    "AuditTool",
    "CommandAuditTool",
]
