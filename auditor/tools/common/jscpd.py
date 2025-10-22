# auditor/tools/common/jscpd.py
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..base import AuditTool, Finding, ToolRunResult


def _rel(root: Path, p: str | None) -> Optional[str]:
    if not p:
        return None
    try:
        return str(Path(p).resolve().relative_to(root.resolve()))
    except Exception:
        return str(p)


def _pair_instances(clone: Dict[str, Any]) -> List[Dict[str, Any]]:
    # Normalize across JSCPD versions
    if "firstFile" in clone and "secondFile" in clone:
        return [clone["firstFile"], clone["secondFile"]]
    if "duplicationA" in clone and "duplicationB" in clone:
        return [clone["duplicationA"], clone["duplicationB"]]
    if isinstance(clone.get("instances"), list) and len(clone["instances"]) >= 2:
        return clone["instances"][:2]
    return []


def _span(inst: Dict[str, Any]) -> Tuple[Optional[int], Optional[int]]:
    start = None
    end = None
    start_loc = inst.get("startLoc") or {}
    end_loc = inst.get("endLoc") or {}
    if isinstance(start_loc.get("line"), int):
        start = start_loc["line"]
    if isinstance(end_loc.get("line"), int):
        end = end_loc["line"]
    if start is None and isinstance(inst.get("start"), int):
        start = inst["start"]
    if end is None and isinstance(inst.get("end"), int):
        end = inst["end"]
    return start, end


class JscpdTool(AuditTool):
    """
    Language-agnostic wrapper for JSCPD (copy/paste detector).

    Improvements:
      - Dedupe mirrored clone pairs (emit one finding per clone).
      - Optional suppression of intra-file clones.
      - Supports --min-tokens and --min-lines.
      - Reads JSON report from the output directory for reliability.
    """

    @property
    def name(self) -> str:
        return "jscpd"

    def __init__(
        self,
        patterns: Optional[Iterable[str]] = None,
        formats: Optional[Iterable[str]] = None,
        ignore_globs: Optional[Iterable[str]] = None,
        min_tokens: Optional[int] = None,
        min_lines: Optional[int] = None,
        gitignore: bool = True,
        emit_both_sides: bool = False,     # only 1 finding per clone by default
        allow_intra_file: bool = True,     # keep intra-file clones unless disabled
        extra_args: Optional[List[str]] = None,
        **kw: Any,
    ) -> None:
        super().__init__(**kw)
        self.patterns = list(patterns or [])
        self.formats = list(formats or [])
        self.ignore_globs = list(ignore_globs or [])
        self.min_tokens = min_tokens
        self.min_lines = min_lines
        self.gitignore = gitignore
        self.emit_both_sides = emit_both_sides
        self.allow_intra_file = allow_intra_file
        self.extra_args = extra_args or []

    # For is_installed()
    def build_cmd(self, path: str) -> List[str]:
        return ["jscpd", "--help"]

    def audit(self, path: str):
        repo = Path(path).resolve()

        with tempfile.TemporaryDirectory(prefix="jscpd-") as tmpdir:
            out_dir = Path(tmpdir)
            cmd: List[str] = [
                "jscpd",
                "--reporters", "json",
                "--silent",
                "--output", str(out_dir),
            ]

            if self.formats:
                cmd += ["--format", ",".join(self.formats)]
            for pat in self.patterns:
                cmd += ["--pattern", pat]

            if self.gitignore:
                cmd.append("--gitignore")

            if self.ignore_globs:
                cmd += ["--ignore", ",".join(self.ignore_globs)]

            if self.min_tokens is not None:
                cmd += ["--min-tokens", str(self.min_tokens)]
            if self.min_lines is not None:
                cmd += ["--min-lines", str(self.min_lines)]

            if self.extra_args:
                cmd += self.extra_args

            cmd.append(str(repo))

            run = self._run(cmd, cwd=str(repo))

            parsed = run.parsed_json
            if parsed is None:
                report_path = out_dir / "jscpd-report.json"
                if report_path.exists():
                    try:
                        parsed = json.loads(report_path.read_text(encoding="utf-8", errors="ignore"))
                    except Exception:
                        parsed = None

            if parsed is not None and run.parsed_json is None:
                run = ToolRunResult(
                    tool=run.tool, cmd=run.cmd, cwd=run.cwd, returncode=run.returncode,
                    duration_s=run.duration_s, stdout=run.stdout, stderr=run.stderr, parsed_json=parsed
                )

            findings = self.parse(run)
            return findings, run

    def parse(self, result: ToolRunResult) -> List[Finding]:
        data = result.parsed_json or {}
        repo = Path(result.cwd).resolve()
        findings: List[Finding] = []

        clones_arr = data.get("clones") or data.get("duplicates") or []
        files_with_dups: set[str] = set()
        seen_pairs: set[Tuple[Tuple[str, int, int], Tuple[str, int, int]]] = set()

        def _norm_pair(a_file: Optional[str], a_start: Optional[int], a_end: Optional[int],
                       b_file: Optional[str], b_start: Optional[int], b_end: Optional[int]):
            # Normalize to a stable, unordered key to avoid mirrored duplicates
            a_key = (a_file or "", int(a_start or 0), int(a_end or 0))
            b_key = (b_file or "", int(b_start or 0), int(b_end or 0))
            return tuple(sorted([a_key, b_key]))

        if isinstance(clones_arr, list):
            for clone in clones_arr:
                fmt = clone.get("format") or clone.get("language")
                lines = clone.get("lines")
                tokens = clone.get("tokens")
                insts = _pair_instances(clone)
                if len(insts) < 2:
                    continue
                a, b = insts[:2]
                a_file = _rel(repo, a.get("name") or a.get("file"))
                b_file = _rel(repo, b.get("name") or b.get("file"))
                a_start, a_end = _span(a)
                b_start, b_end = _span(b)

                if not self.allow_intra_file and (a_file == b_file):
                    continue

                key = _norm_pair(a_file, a_start, a_end, b_file, b_start, b_end)
                if not self.emit_both_sides and key in seen_pairs:
                    continue
                seen_pairs.add(key)

                if a_file:
                    files_with_dups.add(a_file)
                if b_file:
                    files_with_dups.add(b_file)


                token_str = f"{tokens} tokens" if isinstance(tokens, int) else "n/a tokens"
                msg = f"Duplicate block ({lines or 'n/a'} lines, {token_str}) between {a_file} and {b_file}"

                def _mk_finding(_file, _start, _end, counterpart):
                    return Finding(
                        name="jscpd.duplicate",
                        tool=self.name,
                        rule_id="duplicate",
                        message=msg,
                        file=_file,
                        line=_start,
                        col=None,
                        end_line=_end,
                        end_col=None,
                        category="Duplicate Code",
                        kind="analysis",
                        extra={
                            "format": fmt,
                            "tokens": tokens,
                            "lines": lines,
                            "counterpart": counterpart,
                            "raw": clone,
                        },
                    )

                if self.emit_both_sides:
                    findings.append(_mk_finding(a_file, a_start, a_end, {"file": b_file, "start": b_start, "end": b_end}))
                    findings.append(_mk_finding(b_file, b_start, b_end, {"file": a_file, "start": a_start, "end": a_end}))
                else:
                    # Emit a single canonical finding (choose lexical first)
                    candidate_pairs = [
                        ("A", a_file, a_start, a_end, b_file, b_start, b_end),
                        ("B", b_file, b_start, b_end, a_file, a_start, a_end),
                    ]
                    first_tuple = sorted(
                        candidate_pairs,
                        key=lambda t: (t[1] or "", t[2] or 0, t[3] or 0),
                    )[0]
                    _, f_file, f_start, f_end, c_file, c_start, c_end = first_tuple
                    findings.append(
                        _mk_finding(f_file, f_start, f_end, {"file": c_file, "start": c_start, "end": c_end})
                    )

        return findings
