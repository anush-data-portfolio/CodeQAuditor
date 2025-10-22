# auditor/tools/radon.py
from __future__ import annotations

import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

from ..base import AuditTool, Finding, ToolRunResult


def _rel(root: Path, p: str) -> str:
    try:
        pp = Path(p)
        if not pp.is_absolute():
            pp = (root / pp).resolve()
        return str(pp.relative_to(root))
    except Exception:
        return p


def _num(x: Any) -> float:
    try:
        if x is None:
            return math.nan
        return float(x)
    except Exception:
        return math.nan


def _safe_json(txt: str) -> Any | None:
    try:
        return json.loads(txt)
    except Exception:
        return None


class RadonTool(AuditTool):
    """
    Radon metrics in one row per file.

    Runs (JSON):
      - CC:   radon cc  -s -j .
      - MI:   radon mi      -j .
      - HAL:  radon hal     -j .
      - RAW:  radon raw     -j .

    Output:
      - One Finding per file with all metrics under extra["metrics"].
      - One Finding 'radon.summary' with repo-level aggregates.

    Also supports fallback parsing when only a concatenated stdout
    (four JSON blobs separated by blank lines) is available.
    """

    @property
    def name(self) -> str:
        return "radon"

    def build_cmd(self, path: str):
        # Only for is_installed()
        return ["radon", "cc", "-j", "."]

    # ---------------- collectors ----------------

    def _run_cc_collect(self, path: str) -> Tuple[Dict[str, Dict[str, Any]], ToolRunResult]:
        run = self._run(["radon", "cc", "-s", "-j", "."], cwd=path)
        return self._collect_cc_from_json(run.parsed_json), run

    def _collect_cc_from_json(self, data: Any) -> Dict[str, Dict[str, Any]]:
        agg: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "cc_blocks": 0, "cc_total": 0.0, "cc_max": 0.0, "cc_rank_counts": Counter()
        })
        if isinstance(data, dict):
            for file_path, blocks in data.items():
                if not isinstance(blocks, list):
                    continue
                a = agg[file_path]
                for b in blocks:
                    cplx = _num(b.get("complexity"))
                    rank = (b.get("rank") or "").upper() or "?"
                    if not math.isnan(cplx):
                        a["cc_blocks"] += 1
                        a["cc_total"] += cplx
                        a["cc_max"] = max(a["cc_max"], cplx)
                    a["cc_rank_counts"][rank] += 1
        for a in agg.values():
            a["cc_avg"] = (a["cc_total"] / a["cc_blocks"]) if a["cc_blocks"] else 0.0
            a["cc_rank_counts"] = dict(a["cc_rank_counts"])  # JSON-safe
            # Worst rank (lexicographically larger ≈ worse in Radon’s A–F)
            ranks = [r for r, n in a["cc_rank_counts"].items() if n > 0]
            a["cc_worst_rank"] = max(ranks) if ranks else None
        return agg

    def _run_mi_collect(self, path: str) -> Tuple[Dict[str, Dict[str, Any]], ToolRunResult]:
        run = self._run(["radon", "mi", "-j", "."], cwd=path)
        return self._collect_mi_from_json(run.parsed_json), run

    def _collect_mi_from_json(self, data: Any) -> Dict[str, Dict[str, Any]]:
        out: Dict[str, Dict[str, Any]] = {}
        if isinstance(data, dict):
            for file_path, metrics in data.items():
                if isinstance(metrics, dict):
                    out[file_path] = {
                        "mi": _num(metrics.get("mi")),
                        "mi_rank": metrics.get("rank"),
                    }
        return out

    def _run_hal_collect(self, path: str) -> Tuple[Dict[str, Dict[str, Any]], ToolRunResult]:
        run = self._run(["radon", "hal", "-j", "."], cwd=path)
        return self._collect_hal_from_json(run.parsed_json), run

    def _collect_hal_from_json(self, data: Any) -> Dict[str, Dict[str, Any]]:
        out: Dict[str, Dict[str, Any]] = {}
        if isinstance(data, dict):
            for file_path, payload in data.items():
                total = payload.get("total") if isinstance(payload, dict) else None
                if isinstance(total, dict):
                    out[file_path] = {
                        "halstead_volume": _num(total.get("volume")),
                        "halstead_difficulty": _num(total.get("difficulty")),
                        "halstead_effort": _num(total.get("effort")),
                        "halstead_time": _num(total.get("time")),
                        "halstead_bugs": _num(total.get("bugs")),
                    }
        return out

    def _run_raw_collect(self, path: str) -> Tuple[Dict[str, Dict[str, Any]], ToolRunResult]:
        run = self._run(["radon", "raw", "-j", "."], cwd=path)
        return self._collect_raw_from_json(run.parsed_json), run

    def _collect_raw_from_json(self, data: Any) -> Dict[str, Dict[str, Any]]:
        out: Dict[str, Dict[str, Any]] = {}
        if isinstance(data, dict):
            for file_path, metrics in data.items():
                if isinstance(metrics, dict):
                    out[file_path] = {
                        "loc": _num(metrics.get("loc")),
                        "sloc": _num(metrics.get("sloc")),
                        "lloc": _num(metrics.get("lloc")),
                        "comments": _num(metrics.get("comments")),
                        "multi": _num(metrics.get("multi")),
                        "blank": _num(metrics.get("blank")),
                    }
        return out

    # --------------- fallback for concatenated stdout ---------------

    def _fallback_parse_concat_stdout(
        self, combined_stdout: str
    ) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
        """
        Accept a single string that contains 3–4 JSON documents separated by blank lines
        (like the one you posted), and return (cc_map, mi_map, hal_map, raw_map).
        Expected order: CC, MI, HAL, RAW.
        """
        # Split on blank lines, keep only JSON-looking chunks
        chunks: List[str] = []
        buf: List[str] = []
        for line in combined_stdout.splitlines():
            if not line.strip():
                if buf:
                    chunks.append("\n".join(buf).strip())
                    buf = []
            else:
                buf.append(line)
        if buf:
            chunks.append("\n".join(buf).strip())

        docs = [_safe_json(ch) for ch in chunks if ch.strip().startswith("{")]
        cc_map = self._collect_cc_from_json(docs[0]) if len(docs) >= 1 else {}
        mi_map = self._collect_mi_from_json(docs[1]) if len(docs) >= 2 else {}
        hal_map = self._collect_hal_from_json(docs[2]) if len(docs) >= 3 else {}
        raw_map = self._collect_raw_from_json(docs[3]) if len(docs) >= 4 else {}
        return cc_map, mi_map, hal_map, raw_map

    # ---------------- audit ----------------

    def audit(self, path):
        root = Path(path).resolve()

        cc_map, run_cc = self._run_cc_collect(str(root))
        mi_map, run_mi = self._run_mi_collect(str(root))
        hal_map, run_hal = self._run_hal_collect(str(root))
        raw_map, run_raw = self._run_raw_collect(str(root))

        # If everything came back empty (or you're only inspecting the synthetic run),
        # try to parse the concatenated stdout fallback.
        if not (cc_map or mi_map or hal_map or raw_map):
            cc_map, mi_map, hal_map, raw_map = self._fallback_parse_concat_stdout(
                "\n\n".join([run_cc.stdout, run_mi.stdout, run_hal.stdout, run_raw.stdout])
            )

        all_files = set(cc_map) | set(mi_map) | set(hal_map) | set(raw_map)
        per_file_findings: List[Finding] = []

        for f in sorted(all_files):
            rel = _rel(root, f)
            m: Dict[str, Any] = {}

            if f in cc_map:
                a = cc_map[f]
                m["cc_blocks"] = int(a.get("cc_blocks") or 0)
                m["cc_total"] = float(a.get("cc_total") or 0.0)
                m["cc_avg"] = float(a.get("cc_avg") or 0.0)
                m["cc_max"] = float(a.get("cc_max") or 0.0)
                for rk, cnt in sorted((a.get("cc_rank_counts") or {}).items()):
                    m[f"cc_rank_{rk}_count"] = int(cnt)
                if a.get("cc_worst_rank"):
                    m["cc_worst_rank"] = a["cc_worst_rank"]

            if f in mi_map:
                mm = mi_map[f]
                if "mi" in mm and not math.isnan(mm["mi"]):
                    m["mi"] = float(mm["mi"])
                if mm.get("mi_rank"):
                    m["mi_rank"] = mm["mi_rank"]

            if f in hal_map:
                hm = hal_map[f]
                for k in ("halstead_volume", "halstead_difficulty", "halstead_effort", "halstead_time", "halstead_bugs"):
                    v = hm.get(k)
                    if v is not None and not math.isnan(v):
                        m[k] = float(v)

            if f in raw_map:
                rm = raw_map[f]
                for k in ("loc", "sloc", "lloc", "comments", "multi", "blank"):
                    v = rm.get(k)
                    if v is not None and not math.isnan(v):
                        m[k] = float(v)

            metrics = m
            selected_metrics = ['cc_worst_rank', 'mi', 'mi_rank', 'halstead_difficulty', 'loc']
            if any(k in metrics for k in selected_metrics):
                metrics = {k: metrics[k] for k in selected_metrics if k in metrics}


            per_file_findings.append(
                Finding(
                    name="radon.file_metrics",
                    tool="radon",
                    rule_id="file-metrics",
                    message=f"Radon metrics for {rel}",
                    file=rel,
                    line=None,
                    col=None,
                    end_line=None,
                    end_col=None,
                    kind="analysis",
                    category="Code Quality",
                    metrics=metrics

                )
            )

        # Repo summary
        files_n = len(per_file_findings)
        sum_loc = 0.0
        cc_blocks_total = 0
        cc_total_sum = 0.0
        mi_vals: List[float] = []

        for pf in per_file_findings:
            mm = (pf.extra or {}).get("metrics", {})
            sum_loc += float(mm.get("loc") or 0.0)
            cc_blocks_total += int(mm.get("cc_blocks") or 0)
            cc_total_sum += float(mm.get("cc_total") or 0.0)
            mi_v = mm.get("mi")
            if isinstance(mi_v, (int, float)):
                mi_vals.append(float(mi_v))

        summary = Finding(
            name="radon.summary",
            tool="radon-metrics",
            rule_id="summary",
            message="Radon summary",
            file=None,
            line=None,
            col=None,
            end_line=None,
            end_col=None,
            extra={
                "files": files_n,
                "loc": int(sum_loc) if sum_loc else 0,
                "cc_blocks": cc_blocks_total,
                "cc_total": cc_total_sum,
                "cc_avg_overall": (cc_total_sum / cc_blocks_total) if cc_blocks_total else 0.0,
                "mi_avg": (sum(mi_vals) / len(mi_vals)) if mi_vals else None,
                "returncodes": {
                    "cc": run_cc.returncode,
                    "mi": run_mi.returncode,
                    "hal": run_hal.returncode,
                    "raw": run_raw.returncode,
                },
                "durations_s": {
                    "cc": run_cc.duration_s,
                    "mi": run_mi.duration_s,
                    "hal": run_hal.duration_s,
                    "raw": run_raw.duration_s,
                    "total": run_cc.duration_s + run_mi.duration_s + run_hal.duration_s + run_raw.duration_s,
                },
            },
        )

        # Synthetic combined run for logging
        merged_stdout = "\n\n".join(s for s in [run_cc.stdout, run_mi.stdout, run_hal.stdout, run_raw.stdout] if s)
        merged_stderr = "\n\n".join(s for s in [run_cc.stderr, run_mi.stderr, run_hal.stderr, run_raw.stderr] if s)
        synthetic = ToolRunResult(
            tool=self.name,
            cmd=["radon", "<combined:cc+mi+hal+raw>"],
            cwd=str(root),
            returncode=max(run_cc.returncode, run_mi.returncode, run_hal.returncode, run_raw.returncode),
            duration_s=run_cc.duration_s + run_mi.duration_s + run_hal.duration_s + run_raw.duration_s,
            stdout=merged_stdout.strip(),
            stderr=merged_stderr.strip(),
            parsed_json=None,
        )

        return [*per_file_findings, summary], synthetic
