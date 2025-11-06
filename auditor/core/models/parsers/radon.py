"""Parser for Radon code metrics results.

Radon analyzes Python code to compute complexity metrics including cyclomatic
complexity, maintainability index, and raw metrics.

Functions
---------
radon_to_models : Parse Radon JSON output to ORM models

Examples
--------
>>> metrics = {"cc": {"file.py": [{"complexity": 5}]}}
>>> scan, rows = radon_to_models(metrics, cwd="/path")

See Also
--------
auditor.infra.tools.radon : Radon tool wrapper
"""
from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field

from ..orm import RadonResult, ScanMetadata
from ._shared import (
    determine_root_label,
    ensure_abs,
    now_iso,
    relativize_path,
    strip_before_start_root,
    validate,
)


class CCAggregate(BaseModel):
    cc_blocks: int
    cc_total: float
    cc_max: float
    cc_avg: float
    cc_worst_rank: str
    cc_rank_counts: Dict[str, int] = Field(default_factory=dict)


class MIAggregate(BaseModel):
    mi: float
    mi_rank: str = Field(alias="rank")
    model_config = ConfigDict(populate_by_name=True)


class RawAggregate(BaseModel):
    loc: int
    sloc: int
    lloc: int
    comments: int
    multi: int
    blank: int
    single_comments: Optional[int] = None


class HALAggregate(BaseModel):
    halstead_volume: float = Field(alias="volume")
    halstead_difficulty: float = Field(alias="difficulty")
    halstead_effort: float = Field(alias="effort")
    halstead_time: float = Field(alias="time")
    halstead_bugs: float = Field(alias="bugs")

    model_config = ConfigDict(populate_by_name=True)


_RANK_ORDER = ["A", "B", "C", "D", "E", "F"]


def _rank_worse(a: str, b: str) -> str:
    ia = _RANK_ORDER.index(a) if a in _RANK_ORDER else -1
    ib = _RANK_ORDER.index(b) if b in _RANK_ORDER else -1
    return a if ia > ib else b


def _aggregate_cc_list(blocks: List[Mapping[str, Any]]) -> CCAggregate:
    total = 0.0
    cc_max = 0.0
    counts: Dict[str, int] = {}
    worst = "A"
    for b in blocks:
        c = float(b.get("complexity", 0) or 0)
        r = str(b.get("rank", "A"))
        total += c
        if c > cc_max:
            cc_max = c
        counts[r] = counts.get(r, 0) + 1
        worst = _rank_worse(worst, r)
    n = len(blocks) or 1
    return CCAggregate(
        cc_blocks=len(blocks),
        cc_total=total,
        cc_max=cc_max,
        cc_avg=total / n,
        cc_worst_rank=worst,
        cc_rank_counts=counts,
    )


def _first_if_tuple(value):
    if isinstance(value, tuple) and value:
        return value[0]
    return value

# -----------------------------
# Small helpers (keep it simple)
# -----------------------------

def _normalize_maps(bundle: Mapping[str, Any]) -> Tuple[Mapping[str, Any], ...]:
    cc_map = _first_if_tuple(bundle.get("cc", {})) or {}
    mi_map = _first_if_tuple(bundle.get("mi", {})) or {}
    raw_map = _first_if_tuple(bundle.get("raw", {})) or {}
    hal_map = _first_if_tuple(bundle.get("hal", {})) or {}
    return cc_map, mi_map, raw_map, hal_map


def _collect_rel_paths(maps: List[Mapping[str, Any]], *, cwd: Optional[str]) -> List[str]:
    rels: List[str] = []
    for m in maps:
        if not isinstance(m, Mapping):
            continue
        for key in m.keys():
            key_str = str(key)
            rels.append(relativize_path(key_str, cwd) or key_str)
    return rels


def _norm_file_path(file_path: Any, *, cwd: Optional[str], start_root: Optional[str]) -> str:
    # Always store absolute paths (then optionally trim to start_root anchor)
    abs_path = ensure_abs(str(file_path), cwd)
    return strip_before_start_root(abs_path, start_root)


def _build_cc_row(
    scan_row: "ScanMetadata",
    file_path: Any,
    entry: Any,
    root_label: str,
    cwd: Optional[str],
    start_root: Optional[str],
) -> Optional["RadonResult"]:
    agg: Optional["CCAggregate"] = None

    if isinstance(entry, Mapping) and any(k.startswith("cc_") for k in entry.keys()):
        agg = validate(CCAggregate, entry)
    elif isinstance(entry, list):
        agg = _aggregate_cc_list(entry)

    if not agg:
        return None

    return RadonResult(
        scan=scan_row,
        metric_type="cc",
        file_path=_norm_file_path(file_path, cwd=cwd, start_root=start_root),
        root=root_label,
        line_number=None,
        end_line_number=None,
        col_offset=None,
        end_col_offset=None,
        cc_blocks=agg.cc_blocks,
        cc_total=agg.cc_total,
        cc_max=agg.cc_max,
        cc_avg=agg.cc_avg,
        cc_worst_rank=agg.cc_worst_rank,
        cc_rank_counts=agg.cc_rank_counts,
        extra=None,
    )


def _build_mi_row(
    scan_row: "ScanMetadata",
    file_path: Any,
    entry: Any,
    root_label: str,
    cwd: Optional[str],
    start_root: Optional[str],
) -> Optional["RadonResult"]:
    if not (isinstance(entry, Mapping) and "mi" in entry):
        return None

    data = dict(entry)
    # Some producers use "mi_rank"; normalize to "rank" if the model expects it.
    if "mi_rank" in data and "rank" not in data:
        data["rank"] = data["mi_rank"]

    agg = validate(MIAggregate, data)

    return RadonResult(
        scan=scan_row,
        metric_type="mi",
        file_path=_norm_file_path(file_path, cwd=cwd, start_root=start_root),
        root=root_label,
        mi=agg.mi,
        mi_rank=agg.mi_rank,
    )


def _build_raw_row(
    scan_row: "ScanMetadata",
    file_path: Any,
    entry: Any,
    root_label: str,
    cwd: Optional[str],
    start_root: Optional[str],
) -> Optional["RadonResult"]:
    if not isinstance(entry, Mapping):
        return None

    agg = validate(RawAggregate, entry)

    return RadonResult(
        scan=scan_row,
        metric_type="raw",
        file_path=_norm_file_path(file_path, cwd=cwd, start_root=start_root),
        root=root_label,
        raw_loc=agg.loc,
        raw_sloc=agg.sloc,
        raw_lloc=agg.lloc,
        raw_comments=agg.comments,
        raw_multi=agg.multi,
        raw_blank=agg.blank,
        raw_single_comments=agg.single_comments,
    )


def _build_hal_row(
    scan_row: "ScanMetadata",
    file_path: Any,
    entry: Any,
    root_label: str,
    cwd: Optional[str],
    start_root: Optional[str],
) -> Optional["RadonResult"]:
    payload: Optional[Mapping[str, Any]] = None

    if isinstance(entry, Mapping) and any(k.startswith("halstead_") for k in entry.keys()):
        payload = entry
    elif isinstance(entry, Mapping) and isinstance(entry.get("total"), Mapping):
        payload = entry["total"]

    if not payload:
        return None

    agg = validate(HALAggregate, payload)

    return RadonResult(
        scan=scan_row,
        metric_type="hal",
        file_path=_norm_file_path(file_path, cwd=cwd, start_root=start_root),
        root=root_label,
        hal_volume=agg.halstead_volume,
        hal_difficulty=agg.halstead_difficulty,
        hal_effort=agg.halstead_effort,
        hal_time=agg.halstead_time,
        hal_bugs=agg.halstead_bugs,
        extra=None,
    )

def radon_to_models(
    radon_bundle: Mapping[str, Any],
    generated_at: Optional[str] = None,
    *,
    cwd: Optional[str] = None,
    start_root: Optional[str] = None,
) -> Tuple["ScanMetadata", List["RadonResult"]]:
    """
    Accepts a bundle like:
      { "cc": <dict|tuple>, "mi": <dict|tuple>, "raw": <dict|tuple>, "hal": <dict|tuple> }
    and returns (ScanMetadata, [RadonResult,...]).
    """

    ts = generated_at or now_iso()
    cc_map, mi_map, raw_map, hal_map = _normalize_maps(radon_bundle)

    # Build relative paths once to compute a stable root label for all rows.
    rel_paths = _collect_rel_paths([cc_map, mi_map, raw_map, hal_map], cwd=cwd)
    root_label = determine_root_label(cwd, rel_paths)

    scan_row = ScanMetadata(scan_timestamp=ts)
    rows: List[RadonResult] = []

    # cc
    if isinstance(cc_map, Mapping):
        for file_path, entry in cc_map.items():
            row = _build_cc_row(scan_row, file_path, entry, root_label, cwd, start_root)
            if row:
                rows.append(row)

    # mi
    if isinstance(mi_map, Mapping):
        for file_path, entry in mi_map.items():
            row = _build_mi_row(scan_row, file_path, entry, root_label, cwd, start_root)
            if row:
                rows.append(row)

    # raw
    if isinstance(raw_map, Mapping):
        for file_path, entry in raw_map.items():
            row = _build_raw_row(scan_row, file_path, entry, root_label, cwd, start_root)
            if row:
                rows.append(row)

    # hal
    if isinstance(hal_map, Mapping):
        for file_path, entry in hal_map.items():
            row = _build_hal_row(scan_row, file_path, entry, root_label, cwd, start_root)
            if row:
                rows.append(row)

    return scan_row, rows

__all__ = [
    "radon_to_models",
]
