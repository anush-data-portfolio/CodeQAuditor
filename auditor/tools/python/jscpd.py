from __future__ import annotations

from typing import Iterable, List, Optional

from ..common.jscpd import JscpdTool


class PythonJscpdTool(JscpdTool):
    """
    JSCPD configured for Python only.
    """

    def __init__(
        self,
        patterns: Optional[Iterable[str]] = None,
        ignore_globs: Optional[Iterable[str]] = None,
        min_tokens: Optional[int] = 50,  # JSCPD default; lower (e.g., 30) to be stricter
        **kw,
    ):
        super().__init__(
            patterns=patterns or ["**/*.py"],
            formats=["python"],
            ignore_globs=(ignore_globs or [
                "**/.git/**",
                "**/.hg/**",
                "**/.svn/**",
                "**/__pycache__/**",
                "**/.mypy_cache/**",
                "**/.pytest_cache/**",
                "**/.venv/**",
                "**/venv/**",
                "**/.auditenv/**",
                "**/site-packages/**",
                "**/node_modules/**",
                "**/build/**",
                "**/dist/**",
                "**/.tox/**",
            ]),
            min_tokens=min_tokens,
            gitignore=True,
            **kw,
        )
