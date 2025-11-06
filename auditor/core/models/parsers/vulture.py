"""Parser for Vulture dead code detection results.

Vulture finds unused code in Python programs. This parser converts Vulture's
text output into structured database models.

Functions
---------
vulture_text_to_models : Parse Vulture text output to ORM models

Examples
--------
>>> output = "file.py:10: unused function 'foo' (60% confidence)"
>>> scan, rows = vulture_text_to_models(output, cwd="/path")

See Also
--------
auditor.infra.tools.vulture : Vulture tool wrapper
"""
from __future__ import annotations

import os
import re
from typing import List, Optional, Tuple

from ..orm import ScanMetadata, VultureResult
from ._shared import (
    determine_root_label,
    ensure_abs,
    now_iso,
    relativize_path,
    strip_before_start_root,
)
    

_LINE_RE = re.compile(
    r"""^(?P<file>.+?):(?P<line>\d+):\s*
        (?P<message>.*?)
        (?:\s*\((?P<conf>\d+)%\s+confidence\))?
        \s*$""",
    re.VERBOSE,
)

_KIND_RE = re.compile(r"^(?P<kind>[A-Za-z _/]+?)\b")


def vulture_text_to_models(
    stdout: str,
    *,
    cwd: Optional[str] = None,
    generated_at: Optional[str] = None,
    min_confidence: Optional[int] = None,
    start_root: Optional[str] = None,
) -> Tuple["ScanMetadata", List["VultureResult"]]:
    """Parse Vulture stdout text into ORM rows (optimized)."""

    ts = generated_at or now_iso()
    scan_row = ScanMetadata(scan_timestamp=ts)

    rows: List[VultureResult] = []
    # collect paths once to compute a stable root label (used by all rows)
    collected_paths: List[str] = []

    # micro-opts: bind locals
    line_re = _LINE_RE
    kind_re = _KIND_RE
    want_min = min_confidence is not None

    for raw in stdout.splitlines():
        s = raw.strip()
        if not s:
            continue

        m = line_re.match(s)
        if not m:
            continue

        file_path = m.group("file")
        line_no = int(m.group("line"))
        message = m.group("message").strip()

        conf_raw = m.group("conf")
        confidence = int(conf_raw) if conf_raw is not None else None

        # quick reject
        if want_min and confidence is not None and confidence < min_confidence:  # type: ignore[arg-type]
            continue

        # cache relative path for common-root computation
        rel_path = relativize_path(file_path, cwd) or file_path
        collected_paths.append(rel_path)

        # classify kind (lowercase, hyphenated)
        kind = None
        km = kind_re.match(message)
        if km:
            kind = (
                km.group("kind")
                .strip()
                .lower()
                .replace(" ", "-")
                .replace("/", "-")
            )

        # compute an absolute path once; then optionally strip ahead of start_root
        abs_path = ensure_abs(file_path, cwd)
        abs_path = strip_before_start_root(abs_path, start_root)

        rows.append(
            VultureResult(
                scan=scan_row,
                file_path=abs_path,
                root="",  # set after loop, once
                line_number=line_no,
                end_line_number=line_no,
                message=message,
                confidence=confidence,
                kind=kind,
            )
        )

    # single root label for all rows
    root_label = determine_root_label(cwd, collected_paths)

    # assign root on all rows; be compatible with pydantic-frozen models
    try:
        for r in rows:
            r.root = start_root  # type: ignore[attr-defined]
    except Exception:
        # pydantic v2 frozen models
        rows = [
            (getattr(r, "model_copy", None) and r.model_copy(update={"root": start_root})) or r  # type: ignore[truthy-bool]
            for r in rows
        ]

    return scan_row, rows


__all__ = ["vulture_text_to_models"]
