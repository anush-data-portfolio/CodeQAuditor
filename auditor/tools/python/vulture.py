# auditor/tools/vulture.py
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from..base import AuditTool, Finding, ToolRunResult


def _rel(root: Path, p: Optional[str]) -> Optional[str]:
    if not p:
        return None
    try:
        return str(Path(p).resolve().relative_to(root.resolve()))
    except Exception:
        return p


def _fingerprint(
    file_rel: Optional[str],
    rule_id: Optional[str],
    message: str,
    span: Tuple[Optional[int], Optional[int]],
) -> str:
    s = f"{file_rel or ''}|{rule_id or ''}|{message}|{span[0] or 0}:{span[1] or 0}"
    return hashlib.sha1(s.encode("utf-8", "ignore")).hexdigest()


# Example lines Vulture emits:
#   path/to/file.py:8: unused import 'SemgrepTool' (90% confidence)
#   path/to/file.py:42: unused variable 'x' (100% confidence)
_LINE_RE = re.compile(
    r"""^(?P<file>.+?):(?P<line>\d+):\s+
        (?P<msg>.*?)
        (?:\s+\((?P<conf>\d+)%\s+confidence\))?
        \s*$""",
    re.VERBOSE,
)

# Heuristic: derive a stable rule id from the message prefix (e.g., "unused import")
_KIND_RE = re.compile(r"^(?P<kind>[A-Za-z _/]+?)\b")


class VultureTool(AuditTool):
    """
    Vulture: find unused code (imports/variables/functions/classes/etc.)
    CLI (text): `vulture [options] PATH ...`

    Notes:
      - Vulture has no JSON output; we parse its plain-text diagnostics.
      - Patterns passed to --exclude are matched against ABSOLUTE paths.
      - We default to a conservative exclude list and min_confidence=60.
    """

    @property
    def name(self) -> str:
        return "vulture"

    def __init__(
        self,
        *,
        min_confidence: int = 60,
        ignore_decorators: Optional[List[str]] = None,
        ignore_names: Optional[List[str]] = None,
        exclude_globs: Optional[List[str]] = None,
        extra_args: Optional[List[str]] = None,
        **kw: Any,
    ) -> None:
        super().__init__(**kw)
        self.min_confidence = int(min_confidence)
        self.ignore_decorators = ignore_decorators or []
        self.ignore_names = ignore_names or []
        # Vulture matches patterns against ABSOLUTE paths; use wildcards so they hit anywhere
        self.exclude_globs = exclude_globs or [
            "*/.venv/*", "*/venv/*", "*/.auditenv/*",
            "*/.git/*", "*/.hg/*", "*/.svn/*",
            "*/.tox/*", "*/.mypy_cache/*", "*/__pycache__/*",
            "*/node_modules/*", "*/build/*", "*/dist/*",
        ]
        self.extra_args = extra_args or []

    # For is_installed()
    def build_cmd(self, path: str) -> List[str]:
        return ["vulture", path]

    def audit(self, path: str):
        repo = Path(path).resolve()

        cmd: List[str] = ["vulture"]

        # Excludes: comma-separated patterns, matched against ABSOLUTE paths
        if self.exclude_globs:
            cmd += ["--exclude", ",".join(self.exclude_globs)]

        if self.ignore_decorators:
            cmd += ["--ignore-decorators", ",".join(self.ignore_decorators)]
        if self.ignore_names:
            cmd += ["--ignore-names", ",".join(self.ignore_names)]

        if self.min_confidence is not None:
            cmd += ["--min-confidence", str(self.min_confidence)]

        cmd += self.extra_args
        cmd.append(str(repo))

        run = self._run(cmd, cwd=str(repo))
        findings = self.parse(run)
        # keep only findings above min_confidence
        findings = [
            f for f in findings
            if (f.extra.get("confidence") is None) or (int(f.extra.get("confidence")) >= self.min_confidence)
        ]


        # Keep only files within the repo (Vulture should already do this, but for parity):
        findings = [
            f for f in findings
            if (f.file is None) or self._is_under_root(repo, f.file) or f.name == "vulture.summary"
        ]
        return findings, run

    def parse(self, result: ToolRunResult) -> List[Finding]:
        repo = Path(result.cwd).resolve()
        lines = (result.stdout or "").splitlines()
        findings: List[Finding] = []

        per_kind: Dict[str, int] = {}
        per_rule: Dict[str, int] = {}
        conf_vals: List[int] = []
        files_set: set[str] = set()

        for line in lines:
            m = _LINE_RE.match(line.strip())
            if not m:
                continue

            file_abs = m.group("file")
            line_no = int(m.group("line"))
            msg = m.group("msg").strip()
            conf_raw = m.group("conf")
            conf = int(conf_raw) if conf_raw is not None else None

            # File relative to repo for storage/reporting
            file_rel = _rel(repo, file_abs)

            # Heuristic rule kind from message prefix (e.g., "unused import")
            kind = None
            km = _KIND_RE.match(msg)
            if km:
                kind = km.group("kind").strip().lower().replace(" ", "-").replace("/", "-")

            rule_id = kind or "unused-code"
            per_kind[rule_id] = per_kind.get(rule_id, 0) + 1
            per_rule[rule_id] = per_rule.get(rule_id, 0) + 1
            if conf is not None:
                conf_vals.append(conf)
            if file_rel:
                files_set.add(file_rel)

            fp = _fingerprint(file_rel, rule_id, msg, (line_no, None))

            findings.append(
                Finding(
                    name=rule_id,
                    tool=self.name,
                    rule_id=rule_id,
                    message=msg,
                    file=file_rel,
                    line=line_no,
                    col=None,
                    fingerprint=fp,
                    kind="Redundant Code",
                    category="redundancy",
                    extra={
                        "confidence": conf,
                        "raw_line": line,
                    },
                )
            )

        return findings

    # -------- helpers --------

    def _is_under_root(self, root: Path, fpath: str) -> bool:
        try:
            p = Path(fpath)
            if not p.is_absolute():
                p = (root / p).resolve()
            p.relative_to(root.resolve())
            return True
        except Exception:
            return False
