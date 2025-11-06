from __future__ import annotations

"""ESLint JavaScript/TypeScript linter tool wrapper.

ESLint is a popular linting utility for JavaScript and TypeScript.

Classes
-------
EslintTool : ESLint tool wrapper

Examples
--------
>>> from auditor.infra.tools.eslint import EslintTool  
>>> tool = EslintTool()
>>> result = tool.audit("file.js")

See Also
--------
auditor.core.models.parsers.eslint : ESLint parser
"""

