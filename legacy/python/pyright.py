# auditor/tools/pyright.py
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from auditor.models import FINDING_KIND_ISSUE, FINDING_KIND_SUMMARY, Finding, ToolRunResult

from ..base import AuditTool
from ..utils import load_json_payload, safe_relative_path

# Minor versions Pyright commonly supports; highest first for "best fit"
SUPPORTED_PY_VERSIONS = ["3.13", "3.12", "3.11", "3.10", "3.9", "3.8"]


def _fingerprint(
    file_rel: str | None, rule: str | None, msg: str, span: Tuple[int, int, int, int]
) -> str:
    s = f"{file_rel or ''}|{rule or ''}|{msg}|{span[0]}:{span[1]}-{span[2]}:{span[3]}"
    return hashlib.sha1(s.encode("utf-8", "ignore")).hexdigest()


def _read_text(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def _minor(v: str) -> str:
    m = re.match(r"^(\d+\.\d+)", v.strip())
    return m.group(1) if m else v


def _choose_from_spec(spec: str) -> Optional[str]:
    """
    Choose the highest SUPPORTED_PY_VERSIONS that satisfies a simple spec string,
    e.g. ">=3.9,<3.12" or "~=3.10" or ">=3.8".
    Lightweight matcher; not full PEP 440.
    """
    spec = spec.strip().replace(" ", "")
    parts = [p for p in spec.split(",") if p]

    def ok(ver: str) -> bool:
        for p in parts:
            m = re.match(r"(>=|<=|==|~=|>|<)(\d+\.\d+)", p)
            if not m:
                if re.match(r"^\d+\.\d+$", p):  # bare version → ==
                    if ver != p:
                        return False
                    continue
                continue
            op, rhs = m.groups()
            if op == "==":
                if ver != rhs:
                    return False
            elif op == ">=":
                if not (ver >= rhs):
                    return False
            elif op == "<=":
                if not (ver <= rhs):
                    return False
            elif op == ">":
                if not (ver > rhs):
                    return False
            elif op == "<":
                if not (ver < rhs):
                    return False
            elif op == "~=":
                # ~=3.10 → >=3.10 and <3.11 (compatible release)
                vmaj, vmin = map(int, ver.split("."))
                rmaj, rmin = map(int, rhs.split("."))
                if not (vmaj == rmaj and vmin >= rmin and vmin < rmin + 1):
                    return False
        return True

    for v in SUPPORTED_PY_VERSIONS:
        if ok(v):
            return v
    m = re.search(r"(\d+\.\d+)", spec)
    return m.group(1) if m else None


def _detect_python_version(repo: Path, default: str = "3.12") -> str:
    """
    Best-effort detection of target Python version for the repo.
    Priority:
      1) pyrightconfig.json: "pythonVersion"
      2) pyproject.toml: tool.pyright.pythonVersion
      3) pyproject.toml: project.requires-python (PEP 621)
      4) pyproject.toml: tool.poetry.dependencies.python
      5) poetry.lock: "python-versions"
      6) Pipfile: [requires] python_full_version/python_version
      7) setup.cfg: [options] python_requires
      8) runtime.txt / .python-version
    """
    # 1) pyrightconfig.json
    prc = repo / "pyrightconfig.json"
    if prc.exists():
        try:
            j = json.loads(_read_text(prc))
            v = j.get("pythonVersion")
            if isinstance(v, str) and re.match(r"^3\.\d+$", v):
                return v
        except Exception:
            pass

    # Try tomllib (3.11+), else tomli
    def _load_toml(p: Path) -> Dict[str, Any]:
        if not p.exists():
            return {}
        try:
            import tomllib  # py311+
            return tomllib.loads(_read_text(p))
        except Exception:
            try:
                import tomli  # type: ignore
                return tomli.loads(_read_text(p))  # type: ignore
            except Exception:
                return {}

    # 2,3,4) pyproject.toml
    pp = repo / "pyproject.toml"
    pp_data: Dict[str, Any] = _load_toml(pp) if pp.exists() else {}
    if pp_data:
        v = pp_data.get("tool", {}).get("pyright", {}).get("pythonVersion")
        if isinstance(v, str) and re.match(r"^3\.\d+$", v):
            return v

        req = pp_data.get("project", {}).get("requires-python")
        if isinstance(req, str):
            chosen = _choose_from_spec(req)
            if chosen:
                return chosen

        poetry_py = pp_data.get("tool", {}).get("poetry", {}).get("dependencies", {}).get("python")
        if isinstance(poetry_py, str):
            chosen = _choose_from_spec(poetry_py)
            if chosen:
                return chosen

    # 5) poetry.lock
    plock = repo / "poetry.lock"
    if plock.exists():
        txt = _read_text(plock)
        m = re.search(r"^python-versions\s*=\s*\"([^\"]+)\"", txt, re.M)
        if m:
            chosen = _choose_from_spec(m.group(1))
            if chosen:
                return chosen

    # 6) Pipfile
    pipfile = repo / "Pipfile"
    if pipfile.exists():
        txt = _read_text(pipfile)
        m = re.search(r"^\s*python_full_version\s*=\s*\"(\d+\.\d+\.\d+)\"", txt, re.M)
        if m:
            return _minor(m.group(1))
        m = re.search(r"^\s*python_version\s*=\s*\"(\d+\.\d+)\"", txt, re.M)
        if m:
            return m.group(1)

    # 7) setup.cfg
    setup_cfg = repo / "setup.cfg"
    if setup_cfg.exists():
        txt = _read_text(setup_cfg)
        m = re.search(r"^\s*python_requires\s*=\s*([^\n]+)$", txt, re.M)
        if m:
            chosen = _choose_from_spec(m.group(1).strip())
            if chosen:
                return chosen

    # 8) runtime.txt / .python-version
    runtime = repo / "runtime.txt"
    if runtime.exists():
        txt = _read_text(runtime).strip()
        m = re.search(r"python-(\d+\.\d+)(\.\d+)?$", txt)
        if m:
            return m.group(1)
    pyenv = repo / ".python-version"
    if pyenv.exists():
        txt = _read_text(pyenv).strip()
        m = re.search(r"^(\d+\.\d+)(\.\d+)?$", txt)
        if m:
            return m.group(1)

    return default


class PyrightTool(AuditTool):
    """
    Pyright fast type checking without project install.
    Strategy:
      - Create a transient pyrightconfig.json *inside the repo* (env-agnostic).
      - Auto-detect target pythonVersion from repo metadata (or override).
      - Bound analysis to repo; exclude venv/.git/node_modules/etc.
      - Parse --outputjson into normalized Findings.
      - Suppress env/package noise (missing imports / unknown cascades).
    """

    @property
    def name(self) -> str:
        return "pyright"

    def __init__(
        self,
        python_version: str = "auto",
        strict: bool = True,
        ignore_missing_imports: bool = True,
        ignore_missing_type_stubs: bool = True,
        use_library_code_for_types: bool = False,
        exclude_globs: Optional[List[str]] = None,
        only_within_root: bool = True,
        suppress_external_import_noise: bool = True,
        **kw: Any,
    ):
        super().__init__(**kw)
        self.python_version = python_version
        self.strict = strict
        self.ignore_missing_imports = ignore_missing_imports
        self.ignore_missing_type_stubs = ignore_missing_type_stubs
        self.use_library_code_for_types = use_library_code_for_types
        self.exclude_globs = exclude_globs or [
            "**/.venv",
            "**/.auditenv",
            "**/.git",
            "**/.hg",
            "**/.svn",
            "**/.tox",
            "**/.mypy_cache",
            "**/__pycache__",
            "**/node_modules",
            "**/build",
            "**/dist",
        ]
        self.only_within_root = only_within_root
        self.suppress_external_import_noise = suppress_external_import_noise

    # For is_installed()
    def build_cmd(self, path: str) -> List[str]:
        return ["pyright", "--outputjson"]
    
    def _is_under_root(self, repo: Path, file_path: str) -> bool:
        try:
            abs_file = (repo / file_path).resolve()
            return repo in abs_file.parents or abs_file == repo
        except Exception:
            return False

    def audit(self, path):
        repo = Path(path).resolve()

        target_py = (
            _detect_python_version(repo, default="3.12")
            if self.python_version == "auto"
            else (self.python_version or "3.12")
        )

        # Diagnostic overrides to suppress env noise
        overrides: Dict[str, str] = {
            "reportMissingImports": "none" if self.ignore_missing_imports else "warning",
            "reportMissingModuleSource": "none" if self.ignore_missing_imports else "warning",
            "reportMissingTypeStubs": "none" if self.ignore_missing_type_stubs else "warning",
        }
        if self.suppress_external_import_noise:
            overrides.update(
                {
                    "reportUnknownMemberType": "none",
                    "reportUnknownVariableType": "none",
                    "reportUnknownArgumentType": "none",
                    "reportUnknownParameterType": "none",
                    "reportUnknownLambdaType": "none",
                    "reportUnknownListType": "none",
                    "reportUnknownDictType": "none",
                    "reportUntypedFunctionDecorator": "none",
                    "reportUntypedClassDecorator": "none",
                    "reportUntypedBaseClass": "none",
                    "reportUntypedNamedTuple": "none",
                }
            )

        # Write the config *inside the repo* so include/exclude are relative
        cfg = {
            "include": ["./"],
            "exclude": self.exclude_globs,
            "typeCheckingMode": "strict" if self.strict else "basic",
            "pythonVersion": target_py,
            "useLibraryCodeForTypes": self.use_library_code_for_types,
            "diagnosticSeverityOverrides": overrides,
            "executionEnvironments": [{"root": "./", "pythonVersion": target_py}],
        }

        cfg_path = repo / ".pyrightconfig.auditor.json"
        try:
            cfg_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")

            cmd: List[str] = ["pyright", "--outputjson", "-p", str(cfg_path)]
            if self.cpus and isinstance(self.cpus, int) and self.cpus > 0:
                cmd += ["--threads", str(self.cpus)]
            if target_py:
                cmd += ["--pythonversion", target_py]

            # IMPORTANT: do NOT append the repo path; let config drive targets.
            run = self._run(cmd, cwd=str(repo))
            findings = self.parse(run)

            if self.only_within_root:
                findings = [
                    f
                    for f in findings
                    if (f.file is None) or self._is_under_root(repo, f.file) or f.name == "pyright.summary"
                ]
            return findings, run
        finally:
            try:
                if cfg_path.exists():
                    cfg_path.unlink()
            except Exception:
                pass

    def parse(self, result: ToolRunResult) -> List[Finding]:
        data = load_json_payload(result, default={})
        repo = Path(result.cwd).resolve()
        diags = data.get("generalDiagnostics", []) if isinstance(data, dict) else []
        findings: List[Finding] = []
        severity_counts: Dict[str, int] = {}
        files_touched: set[str] = set()
        rules_seen: set[str] = set()

        # Final safety filter for env/package noise (in case any slip through)
        suppress_rules: set[str] = set()
        if self.ignore_missing_imports:
            suppress_rules.update({"reportMissingImports", "reportMissingModuleSource", "reportMissingTypeStubs"})
        if self.suppress_external_import_noise:
            suppress_rules.update(
                {
                    "reportUnknownMemberType",
                    "reportUnknownVariableType",
                    "reportUnknownArgumentType",
                    "reportUnknownParameterType",
                    "reportUnknownLambdaType",
                    "reportUnknownListType",
                    "reportUnknownDictType",
                    "reportUntypedFunctionDecorator",
                    "reportUntypedClassDecorator",
                    "reportUntypedBaseClass",
                    "reportUntypedNamedTuple",
                }
            )

        for d in diags:
            rule = d.get("rule")
            if rule in suppress_rules:
                continue  # drop env-related noise

            sev = (d.get("severity") or "").lower()
            start = (d.get("range") or {}).get("start", {}) or {}
            end = (d.get("range") or {}).get("end", {}) or {}

            s_line = (start.get("line") + 1) if isinstance(start.get("line"), int) else None
            s_col = (start.get("character") + 1) if isinstance(start.get("character"), int) else None
            e_line = (end.get("line") + 1) if isinstance(end.get("line"), int) else None
            e_col = (end.get("character") + 1) if isinstance(end.get("character"), int) else None

            file_rel = safe_relative_path(d.get("file"), repo)
            fp = _fingerprint(
                file_rel, rule, d.get("message", ""), (s_line or 0, s_col or 0, e_line or 0, e_col or 0)
            )

            # Tags and metrics
            tags = [t for t in ["pyright", "type-check", rule, sev] if t]
            span_lines = (e_line - s_line + 1) if (s_line and e_line) else None
            span_cols = (e_col - s_col + 1) if (s_col and e_col and s_line == e_line) else None
            metrics: Dict[str, float] = {"count": 1.0}
            if span_lines is not None:
                metrics["span_lines"] = float(span_lines)
            if span_cols is not None:
                metrics["span_cols"] = float(span_cols)

            severity_counts[sev or "info"] = severity_counts.get(sev or "info", 0) + 1
            if file_rel:
                files_touched.add(file_rel)
            if rule:
                rules_seen.add(rule)

            findings.append(
                Finding(
                    name=f"pyright.{rule}" if rule else "pyright.diagnostic",
                    tool=self.name,
                    rule_id=rule,
                    message=d.get("message", ""),
                    file=file_rel,
                    line=s_line,
                    col=s_col,
                    end_line=e_line,
                    end_col=e_col,
                    fingerprint=fp,
                    category="typing",
                    tags=tags,
                    metrics=metrics,
                    kind=FINDING_KIND_ISSUE,
                    extra={
                        "kind": sev or "diagnostic",
                        "category": rule or "pyright",
                        "tags": tags,
                        "metrics": metrics,
                        "rule": rule,
                        "raw": d,
                    },
                )
            )

        if findings:
            total = sum(severity_counts.values())
            summary_metrics = {"issues": float(total), "files_with_findings": float(len(files_touched))}
            for sev, cnt in severity_counts.items():
                summary_metrics[f"{sev}_count"] = float(cnt)

            findings.append(
                Finding(
                    name="pyright.summary",
                    tool=self.name,
                    rule_id="summary",
                    message="Pyright summary",
                    file=None,
                    line=None,
                    col=None,
                    end_line=None,
                    end_col=None,
                    kind=FINDING_KIND_SUMMARY,
                    category="summary",
                    metrics=summary_metrics,
                    extra={
                        "rules": sorted(rules_seen),
                        "files": sorted(files_touched),
                        "returncode": result.returncode,
                        "duration_s": result.duration_s,
                    },
                )
            )

        return findings
