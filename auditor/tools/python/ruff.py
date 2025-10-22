# auditor/tools/ruff.py
from __future__ import annotations

import collections
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..base import AuditTool, Finding, ToolRunResult


def _fingerprint(
    path: Optional[str],
    code: Optional[str],
    msg: str,
    span: Tuple[Optional[int], Optional[int], Optional[int], Optional[int]],
) -> str:
    s = f"{path or ''}|{code or ''}|{msg}|{span[0] or 0}:{span[1] or 0}-{span[2] or 0}:{span[3] or 0}"
    return hashlib.sha1(s.encode("utf-8", "ignore")).hexdigest()


def _family(rule_code: Optional[str]) -> Optional[str]:
    # E.g. F401 -> 'F', B008 -> 'B', UP036 -> 'UP', S101 -> 'S'
    if not rule_code:
        return None
    # collect leading letters until first digit
    out = []
    for ch in rule_code:
        if ch.isdigit():
            break
        out.append(ch)
    return "".join(out) or None


class RuffTool(AuditTool):
    """
    Ruff linter (no install of target project required).

    Produces JSON via: `ruff check --output-format=json <path>`
    Notes:
      - By default we use `--isolated` to ignore per-repo config for consistency across many scans.
      - You can opt in to `select_all` (maps to `--select ALL`) to enable the widest rule set.
      - We default-exclude venvs, caches, node_modules, build dirs, etc.
      - JSON schema includes fix suggestions with 'applicability' in recent Ruff versions.
        (Docs: fixes are included in JSON; safety is under 'applicability'.)
    """

    @property
    def name(self) -> str:
        return "ruff"

    def __init__(
        self,
        *,
        select_all: bool = True,             # use `--select ALL` for maximum coverage
        preview: bool = False,               # use `--preview` to enable experimental rules
        isolated: bool = True,               # ignore repo configs by default (consistent scanning)
        extend_select: Optional[List[str]] = None,
        ignore: Optional[List[str]] = None,  # rule codes to ignore
        exclude_globs: Optional[List[str]] = None,
        extra_args: Optional[List[str]] = None,  # power users: pass raw args through
        strict_anchor: bool = False,         # if True, drop diagnostics not under the provided anchor
        **kw: Any,
    ) -> None:
        super().__init__(**kw)
        self.select_all = select_all
        self.preview = preview
        self.isolated = isolated
        self.extend_select = extend_select or []
        self.ignore = ignore or []
        self.exclude_globs = exclude_globs or [
            ".git", ".hg", ".svn",
            ".mypy_cache", ".ruff_cache", "__pycache__",
            ".venv", "venv", ".auditenv",
            "node_modules", "build", "dist",
        ]
        self.extra_args = extra_args or []
        self.strict_anchor = strict_anchor

    # is_installed()
    def build_cmd(self, path: str) -> List[str]:
        # Not used for execution (we build in audit), but keeps base check working
        return ["ruff", "check", "--output-format=json", "."]

    def audit(self, path: str):
        # `path` is the folder the user asked us to scan (can be relative). We'll use:
        # - root: absolute path we run ruff in (CWD for the process)
        # - anchor: the original value (possibly relative) we clip to if needed
        root = Path(path).resolve()
        anchor = Path(path)

        # Build command
        cmd: List[str] = ["ruff", "check", "--output-format=json", str(root)]

        if self.isolated:
            cmd.append("--isolated")  # ignore any repo configs for consistent baselines
        if self.preview:
            cmd.append("--preview")

        if self.select_all:
            # Enable all rules (users often do this to baseline then suppress as needed)
            cmd += ["--select", "ALL"]

        if self.extend_select:
            cmd += ["--extend-select", ",".join(self.extend_select)]
        if self.ignore:
            cmd += ["--ignore", ",".join(self.ignore)]

        if self.exclude_globs:
            cmd += ["--exclude", ",".join(self.exclude_globs)]

        if self.cpus and isinstance(self.cpus, int) and self.cpus > 0:
            # Ruff is parallel by default; no direct --threads flag.
            pass

        cmd += self.extra_args

        # Use a temp cache so we don't pollute the repo and each run is isolated
        # Respect existing env and add RUFF_CACHE_DIR just for this run.
        tmp_cache = tempfile.TemporaryDirectory(prefix="ruff-cache-")
        old_cache = self.env.get("RUFF_CACHE_DIR")
        self.env["RUFF_CACHE_DIR"] = tmp_cache.name

        try:
            run = self._run(cmd, cwd=str(root))
        finally:
            # restore env and cleanup
            if old_cache is not None:
                self.env["RUFF_CACHE_DIR"] = old_cache
            else:
                self.env.pop("RUFF_CACHE_DIR", None)
            try:
                tmp_cache.cleanup()
            except Exception:
                pass

        findings = self.parse(run, root=root, anchor=anchor, strict_anchor=self.strict_anchor)
        return findings, run

    def parse(
        self,
        result: ToolRunResult,
        *,
        root: Path,
        anchor: Optional[Path] = None,
        strict_anchor: bool = False,
    ) -> List[Finding]:
        findings: List[Finding] = []
        payload = result.parsed_json

        if not isinstance(payload, list):
            findings.append([])
            return findings

        # Precompute anchor parts for clipping
        anchor_parts: Optional[Tuple[str, ...]] = None
        if anchor is not None:
            try:
                anchor_parts = tuple(Path(anchor).parts)
            except Exception:
                anchor_parts = None

        def _clip_to_anchor(pp: Path) -> Optional[str]:
            """Return suffix under the provided anchor (if found), else None."""
            if not anchor_parts:
                return None
            parts = pp.parts
            for i in range(0, len(parts) - len(anchor_parts) + 1):
                if tuple(parts[i:i + len(anchor_parts)]) == anchor_parts:
                    suffix = parts[i + len(anchor_parts):]
                    return "/".join(suffix) if suffix else ""
            return None

        def _clip_path(p: Optional[str]) -> Tuple[Optional[str], bool]:
            """
            Normalize/clip file paths to repo-relative or anchor-suffix.
            Returns (normalized_path, inside_anchor).
            """
            if not p:
                return None, False
            try:
                pp = Path(p)

                # If Ruff already returned a relative path, keep it normalized.
                if not pp.is_absolute():
                    # If it's relative, we can't determine anchor membership perfectly,
                    # but we try to clip if it contains 'src', else return as-is.
                    # Still mark anchor membership False unless we can match explicitly.
                    rel_norm = pp.as_posix()
                    # Try applying anchor clipping on an absolute composed path if possible
                    # (best effort). Without knowing the absolute, we can't be strict.
                    # So we just return the relative normalized.
                    if anchor_parts:
                        # Try to clip to 'src' if user expects 'src/...'
                        if "src" in pp.parts:
                            idx = pp.parts.index("src")
                            rel_norm = "/".join(pp.parts[idx:])
                    return rel_norm, False

                # 1) Prefer repo-relative (relative to the cwd we ran Ruff in).
                try:
                    rel = pp.resolve().relative_to(root.resolve())
                    rel_posix = rel.as_posix()
                    # Also try to clip to anchor suffix if anchor is a sub-folder of root.
                    clipped = _clip_to_anchor(pp.resolve())
                    if clipped is not None and clipped != "":
                        return clipped, True
                    return rel_posix, bool(clipped is not None)
                except Exception:
                    pass

                # 2) Else, clip everything up to and including the provided anchor folder.
                clipped = _clip_to_anchor(pp)
                if clipped is not None:
                    return (clipped if clipped != "" else pp.name), True

                # 3) Else, clip to the first 'src' segment if present.
                if "src" in pp.parts:
                    idx = pp.parts.index("src")
                    return "/".join(pp.parts[idx:]), False

                # 4) Fallback: filename only.
                return pp.name, False
            except Exception:
                return p, False

        per_rule_count: Dict[str, int] = collections.Counter()
        per_family_count: Dict[str, int] = collections.Counter()
        files_set: set[str] = set()
        fixable = 0
        fix_applicability: Dict[str, int] = collections.Counter()

        for d in payload:
            code = d.get("code")
            msg = str(d.get("message", ""))

            # Ruff JSON variants:
            # - path may be under d["filename"]
            # - or under d["location"]["path"] in some builds
            # - positions may be under: location{row,column} and end_location{row,column}
            loc = d.get("location") or {}
            end_loc = d.get("end_location") or d.get("end") or {}

            raw_path = (
                loc.get("path")
                or d.get("filename")
                or d.get("file")
                or d.get("path")
            )

            row = loc.get("row") or loc.get("line")
            col = loc.get("column") or loc.get("col")
            end_row = end_loc.get("row") or end_loc.get("line")
            end_col = end_loc.get("column") or end_loc.get("col")
            url = d.get("url")

            norm_path, inside_anchor = _clip_path(raw_path)

            # If strict_anchor is set, drop diagnostics that we couldn't prove are inside anchor.
            if strict_anchor and not inside_anchor:
                # Attempt final check: if the normalized path starts with 'src/', treat as acceptable.
                if not (isinstance(norm_path, str) and norm_path.startswith("src/")):
                    continue

            fix = d.get("fix")
            if isinstance(fix, dict):
                fixable += 1
                app = fix.get("applicability")
                if isinstance(app, str) and app:
                    fix_applicability[app.lower()] += 1

            fam = _family(code)
            if code:
                per_rule_count[code] += 1
            if fam:
                per_family_count[fam] += 1
            if norm_path:
                files_set.add(norm_path)

            fp = _fingerprint(norm_path, code, msg, (row, col, end_row, end_col))

            findings.append(
                Finding(
                    name=f"Ruff - {code}" if code else "ruff",
                    tool=self.name,
                    rule_id=str(code) if code else None,
                    message=msg,
                    file=norm_path,      # <-- normalized/clipped path here
                    line=row,
                    col=col,
                    end_line=end_row,
                    end_col=end_col,
                    category="linter",
                    fingerprint=fp,
                    extra={
                        "url": url,
                        "fix": fix,  # may contain 'edits' & 'applicability'
                        "family": fam,
                        "raw": d,
                    },
                )
            )



        return findings
