# auditor/tools/base.py
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union, Iterable, DefaultDict, Set
from collections import defaultdict

_IS_POSIX = os.name == "posix"
if _IS_POSIX:
    import resource  # type: ignore[attr-defined]

Json = Union[dict, list, str, int, float, bool, None]


# ---------------------------------------------------------------------------
# Tool execution result
# ---------------------------------------------------------------------------

@dataclass
class ToolRunResult:
    tool: str
    cmd: List[str]
    cwd: str
    returncode: int
    duration_s: float
    stdout: str
    stderr: str
    parsed_json: Optional[Json]

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Avoid storing giant buffers in DB if not needed: keep lengths too
        d["stdout_bytes"] = len(self.stdout.encode("utf-8", "ignore"))
        d["stderr_bytes"] = len(self.stderr.encode("utf-8", "ignore"))
        return d


# ---------------------------------------------------------------------------
# Normalized finding
# ---------------------------------------------------------------------------

# Canonical kinds for downstream partitioning & tables
FINDING_KIND_ISSUE = "issue"      # potential bug / vuln / dangerous pattern
FINDING_KIND_ANALYSIS = "analysis" # metrics / code health (complexity, MI, Halstead, duplication...)
FINDING_KIND_SUMMARY = "summary"   # tool-level summary/metrics row

# A few well-known metric keys you can reuse in tools (optional, not enforced)
# - Cyclomatic complexity: "cyclomatic" (float or int)
# - Maintainability Index: "mi" (float), "mi_rank" (str)
# - Halstead metrics: "halstead_volume", "halstead_difficulty", "halstead_effort",
#   "halstead_bugs", "halstead_time"
# - Duplication: "dup_lines", "dup_tokens", "dup_percent"
# - Size: "loc", "sloc", "comments", "functions", etc.

@dataclass
class Finding:
    # Minimal normalized shape; tools can stash anything else in `extra`
    name: str
    tool: str
    rule_id: Optional[str]
    message: str
    file: Optional[str]
    line: Optional[int]
    col: Optional[int]
    end_line: Optional[int] = None
    end_col: Optional[int] = None
    fingerprint: Optional[str] = None
    extra: Optional[Dict[str, Any]] = None

    # NEW: classification & metrics (safe defaults keep backward compatibility)
    kind: str = FINDING_KIND_ISSUE              # "issue" | "analysis" | "summary"
    category: Optional[str] = None              # e.g. "security", "style", "complexity", "duplication"
    tags: Optional[List[str]] = None            # free-form labels (["fastapi","auth","crypto"])
    metrics: Optional[Dict[str, float]] = None  # numeric metrics for analysis rows

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Base tool wrapper
# ---------------------------------------------------------------------------

class AuditTool:
    """
    Base class for all analyzer wrappers.
    Subclasses should implement:
      - name (property)
      - build_cmd(path: str) -> List[str]   OR override audit()
      - parse(result: ToolRunResult) -> List[Finding]

    Conventions:
      - For bug/vuln/style problems: emit Finding(kind="issue", severity=...)
      - For code-health/metrics: emit Finding(kind="analysis", metrics={...})
      - For tool-level aggregates: emit Finding(kind="summary", rule_id="summary")
    """

    #: default per-process time limit (seconds)
    DEFAULT_TIMEOUT_S: int = 300
    #: default memory limit in MB (None to disable)
    DEFAULT_MEM_MB: Optional[int] = None
    #: default CPU count hint (not enforced; use Docker/cgroups for hard caps)
    DEFAULT_CPUS: Optional[int] = None

    def __init__(
        self,
        timeout_s: Optional[int] = None,
        mem_mb: Optional[int] = None,
        cpus: Optional[int] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> None:
        self.timeout_s = timeout_s or self.DEFAULT_TIMEOUT_S
        self.mem_mb = mem_mb if mem_mb is not None else self.DEFAULT_MEM_MB
        self.cpus = cpus if cpus is not None else self.DEFAULT_CPUS
        self.env = {
            **os.environ,
            "PYTHONUNBUFFERED": "1",
            "PYTHONWARNINGS": "ignore",
        }
        if env:
            self.env.update(env)

    # ----- Properties to override -------------------------------------------------

    @property
    def name(self) -> str:
        raise NotImplementedError

    def build_cmd(self, path: str) -> List[str]:
        """Default: subclass provides a single CLI. Override for multi-step tools."""
        raise NotImplementedError

    # ----- Public API -------------------------------------------------------------

    def is_installed(self) -> bool:
        exe = self._exe_from_cmd(self.build_cmd("."))
        return shutil.which(exe) is not None

    def audit(self, path: Union[str, Path]) -> Tuple[List[Finding], ToolRunResult]:
        """
        Run the tool once against `path` and return (findings, run_result).
        Multi-command tools should override this method.
        """
        path = str(Path(path))
        cmd = self.build_cmd(path)
        run = self._run(cmd, cwd=path)
        findings = self.parse(run)
        return findings, run

    # ----- Parsing to normalized findings ----------------------------------------

    def parse(self, result: ToolRunResult) -> List[Finding]:
        """Default parser does nothing. Subclasses must implement."""
        return []

    # ----- Utilities --------------------------------------------------------------

    def _exe_from_cmd(self, cmd: Sequence[str]) -> str:
        # First token can be "python -m tool" or just "ruff"
        first = cmd[0]
        if first == sys.executable and len(cmd) >= 3 and cmd[1] == "-m":
            return cmd[2]
        return first

    def _preexec_limits(self) -> Optional[Any]:
        if not _IS_POSIX:
            return None

        def _apply():
            # Soft/hard RLIMIT_AS in bytes to approximate memory cap
            if self.mem_mb:
                bytes_limit = int(self.mem_mb) * 1024 * 1024
                resource.setrlimit(resource.RLIMIT_AS, (bytes_limit, bytes_limit))
            # Disable core dumps
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

        return _apply

    def _run(self, cmd: Sequence[str], cwd: Optional[str] = None) -> ToolRunResult:
        started = time.time()
        try:
            proc = subprocess.run(
                cmd,
                cwd=cwd,
                env=self.env,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.timeout_s,
                preexec_fn=self._preexec_limits(),
            )
        except subprocess.TimeoutExpired as e:
            # Synthesize a result on timeout
            duration = time.time() - started
            return ToolRunResult(
                tool=self.name,
                cmd=list(cmd),
                cwd=os.path.abspath(cwd or os.getcwd()),
                returncode=124,
                duration_s=duration,
                stdout=e.stdout or "",
                stderr=(e.stderr or "") + f"\n[TIMEOUT after {self.timeout_s}s]",
                parsed_json=None,
            )
        duration = time.time() - started
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""

        parsed: Optional[Json] = None
        # Best-effort JSON parse if it looks like JSON
        txt = stdout.strip()
        if txt.startswith("{") or txt.startswith("["):
            try:
                parsed = json.loads(txt)
            except Exception:
                parsed = None

        return ToolRunResult(
            tool=self.name,
            cmd=list(cmd),
            cwd=os.path.abspath(cwd or os.getcwd()),
            returncode=proc.returncode,
            duration_s=duration,
            stdout=stdout,
            stderr=stderr,
            parsed_json=parsed,
        )


# ---------------------------------------------------------------------------
# Helpers for partitioning findings & per-tool summary tables
# ---------------------------------------------------------------------------

def partition_findings_by_kind(findings: Iterable[Finding]) -> Dict[str, List[Finding]]:
    """
    Split into buckets: issues / analysis / summaries / other.
    Tools should set Finding.kind, but we’re defensive here.
    """
    buckets: Dict[str, List[Finding]] = {
        FINDING_KIND_ISSUE: [],
        FINDING_KIND_ANALYSIS: [],
        FINDING_KIND_SUMMARY: [],
        "other": [],
    }
    for f in findings:
        k = (f.kind or FINDING_KIND_ISSUE).lower()
        if k in (FINDING_KIND_ISSUE, FINDING_KIND_ANALYSIS, FINDING_KIND_SUMMARY):
            buckets[k].append(f)
        else:
            # Heuristic fallback for legacy rows
            if f.rule_id == "summary" or (f.name and f.name.endswith(".summary")):
                buckets[FINDING_KIND_SUMMARY].append(f)
            elif f.metrics:
                buckets[FINDING_KIND_ANALYSIS].append(f)
            else:
                buckets[FINDING_KIND_ISSUE].append(f)
    return buckets


@dataclass
class ToolSummary:
    tool: str                          # e.g., "bandit", "radon", "jscpd", "pyright"
    issues: int                        # count of issue-kind findings
    analysis: int                      # count of analysis-kind findings
    files_with_findings: int           # number of files touched by this tool
    duration_s: Optional[float] = None # if available from a summary finding
    returncode: Optional[int] = None   # if available from a summary finding
    rules: Optional[List[str]] = None  # unique rule ids reported (if available)
    extra: Optional[Dict[str, Any]] = None  # free-form copy of summary.extra (if any)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def build_tool_summaries(findings: Iterable[Finding]) -> List[ToolSummary]:
    """
    Build one summary per base tool. Works two ways:
      1) If a tool emits a summary finding (kind=summary, rule_id="summary"),
         we’ll use its extra fields (duration_s, returncode, rules, etc.).
         We also normalize tool names like "bandit-metrics" -> "bandit".
      2) Otherwise, we compute counts from the available findings for that tool.
    """
    # Group findings by their *base* tool name (strip "-metrics" suffix)
    by_tool: DefaultDict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        t = (f.tool or "").strip()
        base_tool = t[:-8] if t.endswith("-metrics") else t
        by_tool[base_tool].append(f)

    summaries: List[ToolSummary] = []

    for base_tool, rows in by_tool.items():
        kind_buckets = partition_findings_by_kind(rows)
        issues = kind_buckets[FINDING_KIND_ISSUE]
        analyses = kind_buckets[FINDING_KIND_ANALYSIS]
        summaries_rows = kind_buckets[FINDING_KIND_SUMMARY]

        # Severity counts (only for issues)
        files_touched: Set[str] = set()
        rules: Set[str] = set()

        for r in issues:
            if r.file:
                files_touched.add(r.file)
            if r.rule_id:
                rules.add(r.rule_id)

        # If we have an explicit summary row from the tool, prefer its extra metadata
        duration_s = None
        returncode = None
        summary_extra: Dict[str, Any] = {}
        if summaries_rows:
            # take the first summary row (most tools emit exactly one)
            s = summaries_rows[0]
            if s.extra and isinstance(s.extra, dict):
                summary_extra = dict(s.extra)
                duration_s = summary_extra.get("timeInSec") or summary_extra.get("duration_s")
                returncode = summary_extra.get("returncode")
                # rules may be provided by tool summaries (e.g., pyright)
                if "rules" in summary_extra and isinstance(summary_extra["rules"], list):
                    rules.update(str(x) for x in summary_extra["rules"])

        summaries.append(
            ToolSummary(
                tool=base_tool,
                issues=len(issues),
                analysis=len(analyses),
                files_with_findings=len(files_touched),
                duration_s=duration_s if isinstance(duration_s, (int, float)) else None,
                returncode=returncode if isinstance(returncode, int) else None,
                rules=sorted(rules) if rules else None,
                extra=summary_extra or None,
            )
        )

    # Stable sort: most actionable first (issues desc), then analysis desc, then name
    summaries.sort(key=lambda s: (-s.issues, -s.analysis, s.tool))
    return summaries
