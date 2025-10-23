from __future__ import annotations

from pathlib import Path
from typing import Optional, Tuple, Union

Pathish = Union[str, Path]


def _to_path(value: Pathish | None) -> Optional[Path]:
    if value is None:
        return None
    try:
        return Path(value)
    except (TypeError, ValueError):
        return None


def safe_relative_path(path: Pathish | None, root: Path) -> Optional[str]:
    """
    Convert `path` to a POSIX-style string relative to `root` when possible.
    Falls back to the original string (or filename) when normalization fails.
    """
    if path is None:
        return None

    root_path = _to_path(root) or Path(root)
    candidate = _to_path(path)
    if candidate is None:
        return str(path)

    try:
        root_resolved = root_path.resolve()
    except Exception:
        root_resolved = root_path

    if not candidate.is_absolute():
        return candidate.as_posix()

    try:
        rel = candidate.resolve().relative_to(root_resolved)
        return rel.as_posix()
    except Exception:
        # Attempt to fall back to filename before returning the absolute path
        name = candidate.name
        return name or candidate.as_posix()


def normalize_path(
    path: Pathish | None, root: Path, anchor: Pathish | None = None
) -> Tuple[Optional[str], bool]:
    """
    Normalize `path` relative to `root`. When `anchor` is provided, tries to clip paths
    under that anchor and returns a tuple of (relative_path, inside_anchor_flag).
    """
    rel = safe_relative_path(path, root)
    inside_anchor = False

    if anchor and path:
        anchor_path = _to_path(anchor)
        candidate = _to_path(path)
        if anchor_path and candidate:
            try:
                anchor_resolved = anchor_path.resolve()
            except Exception:
                anchor_resolved = anchor_path

            try:
                candidate_resolved = candidate.resolve()
            except Exception:
                candidate_resolved = candidate

            try:
                suffix = candidate_resolved.relative_to(anchor_resolved)
                inside_anchor = True
                rel = suffix.as_posix() or rel
            except Exception:
                inside_anchor = False

    return rel, inside_anchor
