# auditor/tools/ruff.py
from __future__ import annotations

import collections
import hashlib
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

from auditor.models import FINDING_KIND_ISSUE, FINDING_KIND_SUMMARY, Finding, ToolRunResult

from ..base import AuditTool
from ..utils import load_json_payload, normalize_path


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
        select: Optional[Iterable[str]] = None,
        ignore: Optional[List[str]] = None,  # rule codes to ignore
        exclude_globs: Optional[List[str]] = None,
        extra_args: Optional[List[str]] = None,  # power users: pass raw args through
        strict_anchor: bool = False,         # if True, drop diagnostics not under the provided anchor
        extend_exclude: Optional[List[str]] = None,
        target_version: Optional[str] = None,
        line_length: Optional[int] = None,
        **kw: Any,
    ) -> None:
        super().__init__(**kw)
        self.select_all = select_all
        self.preview = preview
        self.isolated = isolated
        self.extend_select = extend_select or []
        self.select = list(select or [])
        self.ignore = ignore or []
        self.exclude_globs = exclude_globs or [
            ".git", ".hg", ".svn",
            ".mypy_cache", ".ruff_cache", "__pycache__",
            ".venv", "venv", ".auditenv",
            "node_modules", "build", "dist",
        ]
        self.extra_args = extra_args or []
        self.strict_anchor = strict_anchor
        self.extend_exclude = extend_exclude or []
        self.target_version = target_version
        self.line_length = line_length

    # is_installed()
    def build_cmd(self, path: str) -> List[str]:
        # Not used for execution (we build in audit), but keeps base check working
        return ["ruff", "check", "--output-format=json", "."]

    def audit(self, path: Union[str, Path]):
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

        if self.select:
            cmd += ["--select", ",".join(sorted(set(self.select)))]
        if self.select_all:
            # Enable all rules (users often do this to baseline then suppress as needed)
            cmd += ["--select", "ALL"]

        if self.extend_select:
            cmd += ["--extend-select", ",".join(self.extend_select)]
        if self.ignore:
            cmd += ["--ignore", ",".join(self.ignore)]

        exclude_globs = list(self.exclude_globs)
        if self.extend_exclude:
            exclude_globs.extend(self.extend_exclude)
        if exclude_globs:
            cmd += ["--exclude", ",".join(sorted(set(exclude_globs)))]

        if self.target_version:
            cmd += ["--target-version", self.target_version]

        if self.line_length:
            cmd += ["--line-length", str(self.line_length)]

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

        findings = self._parse_with_context(run, root=root, anchor=anchor, strict_anchor=self.strict_anchor)
        return findings, run

    def parse(self, result: ToolRunResult) -> List[Finding]:
        root = Path(result.cwd).resolve()
        return self._parse_with_context(result, root=root, anchor=None, strict_anchor=False)

    def _parse_with_context(
        self,
        result: ToolRunResult,
        *,
        root: Path,
        anchor: Optional[Path] = None,
        strict_anchor: bool = False,
    ) -> List[Finding]:
        findings: List[Finding] = []
        payload = load_json_payload(result, default=[])

        if not isinstance(payload, list):
            return findings

        # Precompute anchor parts for clipping
        per_rule_count: Dict[str, int] = collections.Counter()
        per_family_count: Dict[str, int] = collections.Counter()
        severity_counts: Dict[str, int] = collections.Counter()
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

            anchor_abs: Optional[Path] = None
            if anchor is not None:
                try:
                    anchor_abs = anchor.resolve()
                except Exception:
                    anchor_abs = anchor

            raw_candidate = Path(raw_path) if raw_path else None
            if raw_candidate and not raw_candidate.is_absolute():
                raw_candidate = (root / raw_candidate).resolve()

            norm_path, inside_anchor = normalize_path(raw_candidate or raw_path, root, anchor=anchor_abs or root)

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

            severity = _severity_from_rule(code)
            severity_counts[severity] += 1
            metrics: Dict[str, float] = {
                "count": 1.0,
                "severity_weight": _ruff_severity_weight(severity),
            }

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
                        "severity": severity,
                        "raw": d,
                    },
                    kind=FINDING_KIND_ISSUE,
                    tags=[tag for tag in ["ruff", fam, code] if tag],
                    metrics=metrics,
                )
            )

        summary_metrics: Dict[str, float] = {
            "issues": float(len(findings)),
            "files_with_diagnostics": float(len(files_set)),
            "fixable": float(fixable),
        }
        for family, cnt in per_family_count.items():
            summary_metrics[f"family_{family}_count"] = float(cnt)
        for severity, cnt in severity_counts.items():
            summary_metrics[f"{severity}_count"] = float(cnt)

        findings.append(
            Finding(
                name="ruff.summary",
                tool=self.name,
                rule_id="summary",
                message="Ruff summary",
                file=None,
                line=None,
                col=None,
                kind=FINDING_KIND_SUMMARY,
                category="summary",
                extra={
                    "per_rule": dict(per_rule_count),
                    "per_applicability": dict(fix_applicability),
                    "severity_counts": dict(severity_counts),
                    "returncode": result.returncode,
                    "duration_s": result.duration_s,
                },
                metrics=summary_metrics,
            )
        )

        return findings


def _severity_from_rule(rule: Optional[str]) -> str:
    if not rule:
        return "info"
    prefix = rule.upper()
    if prefix.startswith("S"):
        return "high"
    if prefix.startswith(("B", "BLE")):
        return "medium"
    if prefix.startswith(("UP", "SIM", "RET", "C", "PTH", "ARG", "ERA", "T20")):
        return "low"
    return "info"


def _ruff_severity_weight(severity: str) -> float:
    severity = severity.lower()
    if severity == "high":
        return 1.0
    if severity == "medium":
        return 0.6
    if severity == "low":
        return 0.3
    return 0.1
