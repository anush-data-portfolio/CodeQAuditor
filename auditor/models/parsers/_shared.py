from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, List, Optional, Type, TypeVar


T = TypeVar("T")


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


def determine_root(cwd: Optional[str], paths: Iterable[str]) -> str:
    if cwd:
        base = Path(cwd)
        name = base.name
        if name:
            return name
        return str(base)
    fallback = common_root(paths)
    return fallback


def relativize_path(value: Optional[str], cwd: Optional[str]) -> Optional[str]:
    """
    Return `value` relative to `cwd` when both are provided and `value` is absolute.
    Falls back to the original string when conversion fails.
    """
    if not value:
        return value
    if not cwd:
        return str(Path(value))
    try:
        target = Path(value)
        if not target.is_absolute():
            rel_path = target
            base = Path(cwd)
            if not base.is_absolute():
                base = (Path.cwd() / base).resolve()
            root_label = base.name
            if root_label and (not rel_path.parts or rel_path.parts[0] != root_label):
                rel_path = Path(root_label) / rel_path
            return str(rel_path)

        base = Path(cwd)
        if not base.is_absolute():
            base = (Path.cwd() / base).resolve()

        rel = os.path.relpath(str(target), str(base))

        root_label = base.name
        rel_path = Path(rel)
        if rel_path == Path("."):
            rel_path = Path(root_label) if root_label else Path(".")
        elif root_label and (not rel_path.parts or rel_path.parts[0] != root_label):
            rel_path = Path(root_label) / rel_path

        return str(rel_path)
    except Exception:
        return str(Path(value))
