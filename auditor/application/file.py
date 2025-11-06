"""File discovery and filtering utilities for static analysis.

This module provides intelligent file discovery with support for multiple languages
and comprehensive exclusion rules to avoid scanning irrelevant directories.

The module supports:
- Multi-language file discovery (Python, TypeScript, JavaScript, Ruby, Java)
- Smart exclusion of build artifacts, virtual environments, and cache directories
- Environment file detection and filtering
- Recursive directory traversal with configurable patterns

Supported Languages
-------------------
- Python (.py)
- TypeScript (.ts, .tsx)
- JavaScript (.js, .jsx)
- Ruby (.rb)
- Java (.java)

Excluded Directories
--------------------
Common exclusions include:
- Version control: .git, .hg, .svn
- Dependencies: node_modules, site-packages
- Build artifacts: build, dist, target
- Virtual environments: venv, .venv, env
- Caches: __pycache__, .mypy_cache, .pytest_cache

Examples
--------
Discover all supported files in a directory:
    >>> files = discover_files(Path("/path/to/project"))
    >>> len(files)
    150

Check if directory should be excluded:
    >>> _dir_is_excluded("node_modules")
    True
    >>> _dir_is_excluded("src")
    False

See Also
--------
auditor.application.orchestrator : Tool orchestration using discovered files
"""
from __future__ import annotations

import os
import re
from fnmatch import fnmatch
from pathlib import Path
from typing import List, Set

# Languages you care about
ALLOWED_EXTS: Set[str] = {".py", ".ts", ".tsx", ".js", ".jsx", ".rb", ".java"}

# Directories that are almost never relevant to source discovery
EXCLUDED_DIRS_EXACT: Set[str] = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".pnpm-store",
    ".venv",
    "venv",
    "env",
    "envs",
    ".direnv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".cache",
    "site-packages",
    ".tox",
    "._next",
    ".nuxt",
    "out",
    "target",
    "build",
    "dist",
    ".next",
    ".nuxt",
    "out",
    "target",
    "coverage",
    ".gradle",
    ".idea",
    ".vscode",
}

# Optional glob-style patterns for directories (e.g., .venv3.12, venv-*)
EXCLUDED_DIRS_GLOBS: Set[str] = {
    ".venv*",
    "venv*",
    "env*",
    "*.egg-info",
    "*.dist-info",
}

# If you still want to skip "env-like" files that sneak in,
# do it only for files WITHOUT a code extension.
# (This won’t exclude something like `my_env.py`.)
_ENV_TOKEN = re.compile(r"(^|[._-])env([._-]|$)", re.IGNORECASE)
_ENV_CANONICAL_NAMES = {"env", ".env", "envrc", ".envrc", "dotenv", ".dotenv"}


def _is_env_like(filename: str) -> bool:
    """Heuristic: treat typical dotenv/“env” files as env-like,
    but don’t catch unrelated words like 'event'."""
    base = filename.lower()
    stem = Path(base).stem  # name without extension
    # Canonical names with or without dots
    if base in _ENV_CANONICAL_NAMES or stem in _ENV_CANONICAL_NAMES:
        return True
    # Things like ".env.local", "prod.env", "this_env"
    if _ENV_TOKEN.search(base):
        return True
    return False


def _dir_is_excluded(dirname: str) -> bool:
    """Check if directory should be excluded from file discovery.

    Parameters
    ----------
    dirname : str
        Directory name (basename, not full path) to check.

    Returns
    -------
    bool
        True if directory should be excluded, False otherwise.

    Examples
    --------
    >>> _dir_is_excluded("node_modules")
    True
    >>> _dir_is_excluded("src")
    False
    """
    if dirname in EXCLUDED_DIRS_EXACT:
        return True
    for pat in EXCLUDED_DIRS_GLOBS:
        if fnmatch(dirname, pat):
            return True
    # Skip hidden dirs (like .cache), but keep common dot-dirs we already allowlist explicitly above if needed
    if dirname.startswith(".") and dirname not in {".github"}:
        return True
    return False


def discover_files(root: Path) -> List[Path]:
    """Discover all analyzable code files under root directory.

    Recursively walks the directory tree starting from root, identifying all
    files with supported language extensions while intelligently excluding
    build artifacts, dependencies, and other non-source directories.

    Parameters
    ----------
    root : Path
        Root directory to start discovery from.

    Returns
    -------
    List[Path]
        Sorted list of Path objects pointing to discovered code files.

    Notes
    -----
    Supported file extensions: .py, .ts, .tsx, .js, .jsx, .rb, .java

    Examples
    --------
    >>> files = discover_files(Path("/path/to/project"))
    >>> len(files)
    42
    """
    projects: Set[Path] = set()

    # Use os.walk with in-place dir filtering for performance
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Prune directories we don't care about
        dirnames[:] = [d for d in dirnames if not _dir_is_excluded(d)]

        # Look for allowed code files
        for filename in filenames:
            ext = Path(filename).suffix.lower()

            # Only consider files that are actually code
            if ext not in ALLOWED_EXTS:
                # Opportunistically skip env-like *non-code* files
                if _is_env_like(filename):
                    continue
                # Not code, ignore
                continue

            # We found a code file -> collect its parent directory
            file_path = Path(dirpath) / filename
            projects.add(file_path)

    # Sort for stable output
    return sorted(projects)


__all__ = ["discover_files"]
