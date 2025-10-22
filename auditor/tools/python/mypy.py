# auditor/tools/mypy.py
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..base import AuditTool, Finding, ToolRunResult


class MypyTool(AuditTool):
    """
    Mypy with tolerant imports + rich metrics, now with:
      - note collapsing (attach notes to preceding error)
      - repo-relative paths for in-repo files
      - external note suppression (typeshed/site-packages) by default
      - fully populated positions: line/col/end_line/end_col
      - categorization via error code (category) and human name (code_name)
    """

    @property
    def name(self) -> str:
        return "mypy"

    def __init__(
        self,
        python_version: Optional[str] = "3.12",
        ignore_missing_imports: bool = True,
        follow_imports: str = "silent",   # normal|silent|skip|error
        install_types: bool = False,      # optional; needs network
        strict: bool = False,
        collapse_notes: bool = True,
        drop_external_notes: bool = True, # don't emit typeshed/site-packages notes
        **kw: Any,
    ):
        super().__init__(**kw)
        self.python_version = python_version
        self.ignore_missing_imports = ignore_missing_imports
        self.follow_imports = follow_imports
        self.install_types = install_types
        self.strict = strict
        self.collapse_notes = collapse_notes
        self.drop_external_notes = drop_external_notes

    # Used by base.is_installed()
    def build_cmd(self, path: str) -> List[str]:
        return ["mypy", "--output", "json", "."]

    def audit(self, path):
        root = Path(path).resolve()
        with tempfile.TemporaryDirectory(prefix="mypy-") as tmp:
            reports_dir = Path(tmp) / "reports"
            cache_dir = Path(tmp) / "cache"
            reports_dir.mkdir(parents=True, exist_ok=True)
            cache_dir.mkdir(parents=True, exist_ok=True)

            cmd: List[str] = [
                "mypy",
                ".",
                "--output", "json",
                "--no-site-packages",
                "--explicit-package-bases",
                "--show-error-end",
                "--show-column-numbers",
                "--sqlite-cache",
                "--cache-dir", str(cache_dir),
                "--linecoverage-report", str(reports_dir),
                "--linecount-report", str(reports_dir),
                "--any-exprs-report", str(reports_dir),
                "--txt-report", str(reports_dir),
            ]
            if self.python_version:
                cmd += ["--python-version", self.python_version]
            if self.ignore_missing_imports:
                cmd += ["--ignore-missing-imports"]
            if self.follow_imports:
                cmd += ["--follow-imports", self.follow_imports]
            if self.strict:
                cmd += ["--strict"]
            if self.install_types:
                cmd += ["--install-types", "--non-interactive"]

            prev_cache_env = self.env.get("MYPY_CACHE_DIR")
            self.env["MYPY_CACHE_DIR"] = str(cache_dir)
            try:
                run = self._run(cmd, cwd=str(root))
            finally:
                if prev_cache_env is None:
                    self.env.pop("MYPY_CACHE_DIR", None)
                else:
                    self.env["MYPY_CACHE_DIR"] = prev_cache_env

            events = self._parse_stdout_events(run.stdout)
            groups = self._group_events(events, root)

            findings = self._groups_to_findings(groups, root)
            findings += self._metrics_findings(root, reports_dir, run, events)
            return findings, run

    # ---------------- parsing stdout ----------------

    def _parse_stdout_events(self, stdout: str) -> List[Dict[str, Any]]:
        """Accept both JSON-lines and single-blob JSON."""
        out: List[Dict[str, Any]] = []
        s = (stdout or "").strip()

        # Single blob first
        if s.startswith("{") or s.startswith("["):
            try:
                blob = json.loads(s)
                if isinstance(blob, dict):
                    if isinstance(blob.get("errors"), list):
                        out.extend([e for e in blob["errors"] if isinstance(e, dict)])
                    if isinstance(blob.get("summary"), dict):
                        out.append({"kind": "summary", **blob["summary"]})
                    return out
                if isinstance(blob, list):
                    out.extend([e for e in blob if isinstance(e, dict)])
                    return out
            except Exception:
                pass

        # JSON-lines
        for line in (stdout or "").splitlines():
            line = line.strip()
            if not line or not (line.startswith("{") or line.startswith("[")):
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                out.append(obj)
            elif isinstance(obj, list):
                out.extend([e for e in obj if isinstance(e, dict)])
        return out

    # --------------- grouping + normalization ----------------

    def _group_events(
        self,
        events: List[Dict[str, Any]],
        root: Path,
    ) -> List[Dict[str, Any]]:
        """
        Collapse trailing 'note' events into the preceding non-note diagnostic.
        Normalize file paths to be repo-relative.
        """
        groups: List[Dict[str, Any]] = []
        last_group: Optional[Dict[str, Any]] = None

        def _clip_path(p: Optional[str]) -> Optional[str]:
            if not p:
                return None
            try:
                pp = Path(p)
                if not pp.is_absolute():
                    return pp.as_posix()
                try:
                    rel = pp.resolve().relative_to(root.resolve())
                    return rel.as_posix()
                except Exception:
                    # best effort: clip to 'src' if present, else filename
                    if "src" in pp.parts:
                        i = pp.parts.index("src")
                        return "/".join(pp.parts[i:])
                    return pp.name
            except Exception:
                return p

        def _norm_event(e: Dict[str, Any]) -> Dict[str, Any]:
            # unify common key variants across mypy versions
            file_path = e.get("file") or e.get("path") or e.get("filename")
            code = e.get("code")
            code_id = None
            code_name = None
            if isinstance(code, dict):
                code_id = code.get("code") or code.get("name")
                code_name = code.get("name") or code.get("code")
            elif isinstance(code, (str, int)):
                code_id = str(code)
                code_name = str(code)

            return {
                "kind": (e.get("kind") or e.get("severity") or "error").lower(),
                "category": "linter",      # e.g., "attr-defined"
                "code_name": code_name,   # human-ish name if provided
                "message": e.get("message", ""),
                "file": _clip_path(file_path),
                "line": e.get("line") or e.get("lineno"),
                "column": e.get("column") or e.get("col"),
                "end_line": e.get("end_line") or e.get("endLine"),
                "end_column": e.get("end_column") or e.get("endColumn"),
                "hint": e.get("hint"),
                "note": e.get("note"),
                "raw": e,
            }

        def _is_external(p: Optional[str]) -> bool:
            if not p:
                return False
            s = str(p)
            return ("typeshed" in s) or ("site-packages" in s)

        # normalize first
        normalized: List[Dict[str, Any]] = [_norm_event(e) for e in events if isinstance(e, dict)]

        for e in normalized:
            k = e["kind"]
            if k == "summary":
                # ignore here; metrics step will synthesize summary anyway
                continue

            if k == "note" and self.collapse_notes:
                if self.drop_external_notes and _is_external(e.get("file")):
                    continue
                if last_group is not None:
                    last_group.setdefault("notes", []).append(e)
                    continue
                # no base yet — fall through and create a standalone group
            # new group (base diag or standalone note)
            g = {"base": e}
            groups.append(g)
            last_group = g

        return groups

    def _groups_to_findings(self, groups: List[Dict[str, Any]], root: Path) -> List[Finding]:
        out: List[Finding] = []
        for g in groups:
            e = g.get("base", {})
            category = e.get("category")
            code_name = e.get("code_name")
            rule = category or code_name
            pretty_name = f"mypy.{code_name or category}" if (code_name or category) else "mypy-diagnostic"

            # build notes payload (preserve positions)
            notes_payload = []
            for n in g.get("notes", []) or []:
                notes_payload.append(
                    {
                        "kind": n.get("kind"),
                        "message": n.get("message"),
                        "file": n.get("file"),
                        "line": n.get("line"),
                        "column": n.get("column"),
                        "end_line": n.get("end_line"),
                        "end_column": n.get("end_column"),
                        "category": "linter",
                        "code_name": n.get("code_name"),
                    }
                )

            out.append(
                Finding(
                    name=pretty_name,
                    tool=self.name,
                    rule_id=str(rule) if rule else None,
                    message=e.get("message", ""),
                    file=e.get("file"),
                    line=e.get("line"),
                    col=e.get("column"),
                    end_line=e.get("end_line"),
                    end_col=e.get("end_column"),
                    category="linter",
                    kind=e.get("kind"),
                    extra={
                        "kind": e.get("kind"),
                        "category": "linter",
                        "code_name": code_name,
                        "hint": e.get("hint"),
                        "note": e.get("note"),
                        "notes": notes_payload or None,
                        "raw": e.get("raw"),
                    },
                )
            )
        return out

    # ---------------- metrics ----------------

    def _metrics_findings(
        self,
        repo_root: Path,
        reports_dir: Path,
        run: ToolRunResult,
        diagnostics: List[Dict[str, Any]],
    ) -> List[Finding]:
        findings: List[Finding] = []

        # Per-file + repo coverage from linecoverage.json
        lc_json = reports_dir / "linecoverage.json"
        typed_total = 0
        total_total = 0
        if lc_json.exists():
            try:
                data = json.loads(lc_json.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    for fpath_str, typed_lines in data.items():
                        if not isinstance(typed_lines, list):
                            continue
                        typed = len(typed_lines)
                        fpath = (repo_root / fpath_str).resolve() if not Path(fpath_str).is_absolute() else Path(fpath_str)
                        total = self._count_lines_safe(fpath)
                        typed_total += typed
                        total_total += total

                        rel = self._rel(repo_root, fpath)
                        pct = round(100.0 * typed / total, 2) if total else 0.0
                        findings.append(
                            Finding(
                                name="mypy.file_type_coverage",
                                tool="mypy-metrics",
                                rule_id="file_type_coverage",
                                message=f"{rel} type coverage {pct}%",
                                file=str(rel),
                                line=None,
                                col=None,
                                end_line=None,
                                end_col=None,
                                category="linter",
                                kind="metric",
                                extra={"typed_lines": typed, "total_lines": total, "coverage_pct": pct},
                            )
                        )
            except Exception:
                pass

        if total_total > 0:
            repo_pct = round(100.0 * typed_total / total_total, 2)
            findings.append(
                Finding(
                    name="mypy.type_coverage",
                    tool="mypy-metrics",
                    rule_id="type_coverage",
                    message=f"Type coverage {repo_pct}% (typed {typed_total}/{total_total} lines)",
                    file=None,
                    line=None,
                    col=None,
                    end_line=None,
                    end_col=None,
                    category="linter",
                    kind="metric",
                    extra={"typed_lines": typed_total, "total_lines": total_total, "type_coverage_pct": repo_pct},
                )
            )

        # Any expressions count
        any_txt = reports_dir / "any-exprs.txt"
        if any_txt.exists():
            try:
                txt = any_txt.read_text(encoding="utf-8", errors="ignore")
                nums = [int(tok) for tok in txt.replace(",", " ").split() if tok.isdigit()]
                if nums:
                    findings.append(
                        Finding(
                            name="mypy.any_expressions",
                            tool="mypy-metrics",
                            rule_id="any_expressions",
                            message=f"Any expressions: {max(nums)}",
                            file=None,
                            line=None,
                            col=None,
                            end_line=None,
                            end_col=None,
                            extra={"any_exprs": max(nums)},
                            category="linter",
                            kind="metric",
                        )
                    )
            except Exception:
                pass

        # Summary (optional; skip unless you want one)
        # You can re-enable a final summary Finding here if needed.

        return findings

    # ---------------- utils ----------------

    def _count_lines_safe(self, p: Path) -> int:
        try:
            with p.open("r", encoding="utf-8", errors="ignore") as fh:
                return sum(1 for _ in fh)
        except Exception:
            return 0

    def _rel(self, root: Path, p: Path) -> Path:
        try:
            return p.resolve().relative_to(root.resolve())
        except Exception:
            return p
