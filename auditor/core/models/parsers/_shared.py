"""Shared utilities for tool output parsers.

This module provides common helper functions used across all parser implementations
including path normalization, timestamp generation, and root path determination.

Functions
---------
determine_root : Compute common root path from list of paths
now_iso : Generate ISO-8601 UTC timestamp
common_root : Alias for determine_root
validate : Pydantic v1/v2 compatibility helper
determine_root_label : Generate human-friendly root label
ensure_abs : Convert relative path to absolute
relativize_path : Make path relative to root

Examples
--------
>>> paths = ["/proj/src/a.py", "/proj/src/b.py"]
>>> common_root(paths)
'/proj/src'

See Also
--------
auditor.core.models.parsers : Parser implementations
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, List, Optional, Type, TypeVar

T = TypeVar("T")

def determine_root(paths: Iterable[str]) -> str:
    """
    Compute a common root path for the provided paths.
    Falls back to the parent directory of the first entry on mismatch.
    """
    items: List[str] = [p for p in paths if p]
    if not items:
        return ""
    try:
        return os.path.commonpath(items)
    except ValueError:
        return str(Path(items[0]).resolve().parent)

def now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def common_root(paths: Iterable[str]) -> str:
    """
    Compute a common root path for the provided paths.
    Falls back to the parent directory of the first entry on mismatch.
    """
    items: List[str] = [p for p in paths if p]
    if not items:
        return ""
    try:
        return os.path.commonpath(items)
    except ValueError:
        return str(Path(items[0]).resolve().parent)


def validate(model_cls: Type[T], data: Any) -> T:
    """pydantic v1/v2 compatibility helper."""
    return model_cls.model_validate(data)  # type: ignore[attr-defined]


def determine_root_label(cwd: Optional[str], paths: Iterable[str]) -> str:
    """
    Return a short, human-friendly root label used in stored results.
    If cwd is provided -> basename of cwd. Otherwise -> basename of common root.
    """
    if cwd:
        name = Path(cwd).name
        return name if name else str(Path(cwd))
    fallback = common_root(paths)
    return Path(fallback).name if fallback else ""


def ensure_abs(path: str, cwd: Optional[str]) -> str:
    """
    Return an absolute path. If `path` is relative and `cwd` is provided, resolve from `cwd`.
    """
    p = Path(path)
    if p.is_absolute():
        return str(p)
    base = Path(cwd) if cwd else Path.cwd()
    return str((base / p).resolve())


def relativize_path(value: Optional[str], cwd: Optional[str]) -> Optional[str]:
    """
    Return `value` relative to `cwd` when both are provided and `value` is absolute.
    Falls back to the original string when conversion fails. If `cwd` is relative,
    resolve it first to avoid surprises.
    """
    if not value:
        return value
    if not cwd:
        return str(Path(value))
    try:
        target = Path(value)
        base = Path(cwd)
        if not base.is_absolute():
            base = (Path.cwd() / base).resolve()

        if target.is_absolute():
            rel = os.path.relpath(str(target), str(base))
        else:
            # keep relative but normalize under the root label
            rel = str(Path(value))

        root_label = base.name
        rel_path = Path(rel)
        if rel_path == Path("."):
            rel_path = Path(root_label) if root_label else Path(".")
        elif root_label and (not rel_path.parts or rel_path.parts[0] != root_label):
            rel_path = Path(root_label) / rel_path

        return str(rel_path)
    except Exception:
        return str(Path(value))


def strip_before_start_root(abs_path: str, start_root: Optional[str]) -> str:
    """
    If `start_root` is provided, drop all path components before the last occurrence of
    the `start_root` folder name. Returns the (possibly) shortened path.
    """
    if not start_root:
        return abs_path

    start_folder = os.path.basename(os.path.normpath(start_root))
    parts = Path(abs_path).parts
    # prefer the right-most occurrence to avoid stripping too much on repeated names
    indices = [i for i, part in enumerate(parts) if part == start_folder]
    if not indices:
        return abs_path
    start_index = indices[-1]
    return str(Path(*parts[start_index:]))
