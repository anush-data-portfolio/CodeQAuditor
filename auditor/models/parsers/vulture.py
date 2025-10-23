from __future__ import annotations

import re
from typing import List, Optional, Tuple

from ..orm import ScanMetadata, VultureResult
from ._shared import determine_root, now_iso, relativize_path

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
) -> Tuple[ScanMetadata, List[VultureResult]]:
    """Parse Vulture stdout text into ORM rows."""

    ts = generated_at or now_iso()
    scan_row = ScanMetadata(scan_timestamp=ts)

    rows: List[VultureResult] = []
    paths: List[str] = []

    for raw_line in stdout.splitlines():
        match = _LINE_RE.match(raw_line.strip())
        if not match:
            continue

        file_path = match.group("file")
        line_no = int(match.group("line"))
        message = match.group("message").strip()
        conf_raw = match.group("conf")
        confidence = int(conf_raw) if conf_raw is not None else None

        if (
            min_confidence is not None
            and confidence is not None
            and confidence < min_confidence
        ):
            continue

        rel_path = relativize_path(file_path, cwd) or file_path
        paths.append(rel_path)

        kind = None
        km = _KIND_RE.match(message)
        if km:
            kind = km.group("kind").strip().lower().replace(" ", "-").replace("/", "-")

        rows.append(
            VultureResult(
                scan=scan_row,
                file_path=rel_path,
                root="",  # placeholder, set after loop
                line_number=line_no,
                end_line_number=line_no,
                col_offset=None,
                end_col_offset=None,
                message=message,
                confidence=confidence,
                kind=kind,
            )
        )

    root_value = determine_root(cwd, paths)
    for row in rows:
        row.root = root_value or ""

    return scan_row, rows


__all__ = ["vulture_text_to_models"]
