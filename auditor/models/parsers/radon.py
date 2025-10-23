from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field

from ..orm import RadonResult, ScanMetadata
from ._shared import determine_root, now_iso, relativize_path, validate


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


def radon_to_models(
    radon_bundle: Mapping[str, Any],
    generated_at: Optional[str] = None,
    *,
    cwd: Optional[str] = None,
) -> Tuple[ScanMetadata, List[RadonResult]]:
    """
    Accepts a bundle like:
      {
        "cc": <dict|tuple>,
        "mi": <dict|tuple>,
        "raw": <dict|tuple>,
        "hal": <dict|tuple>,
      }
    and returns (ScanMetadata, [RadonResult,...]).
    """
    ts = generated_at or now_iso()

    cc_map = _first_if_tuple(radon_bundle.get("cc", {})) or {}
    mi_map = _first_if_tuple(radon_bundle.get("mi", {})) or {}
    raw_map = _first_if_tuple(radon_bundle.get("raw", {})) or {}
    hal_map = _first_if_tuple(radon_bundle.get("hal", {})) or {}

    all_files: List[str] = []
    for mapping in (cc_map, mi_map, raw_map, hal_map):
        if isinstance(mapping, Mapping):
            for key in mapping.keys():
                key_str = str(key)
                all_files.append(relativize_path(key_str, cwd) or key_str)
    root = determine_root(cwd, all_files)

    scan_row = ScanMetadata(scan_timestamp=ts)
    rows: List[RadonResult] = []

    if isinstance(cc_map, Mapping):
        for file_path, entry in cc_map.items():
            agg: Optional[CCAggregate] = None
            if isinstance(entry, Mapping) and any(
                k.startswith("cc_") for k in entry.keys()
            ):
                agg = validate(CCAggregate, entry)
            elif isinstance(entry, list):
                agg = _aggregate_cc_list(entry)
            if not agg:
                continue
            rel_path = relativize_path(str(file_path), cwd)
            rows.append(
                RadonResult(
                    scan=scan_row,
                    metric_type="cc",
                    file_path=rel_path or str(file_path),
                    root=root,
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
            )

    if isinstance(mi_map, Mapping):
        for file_path, entry in mi_map.items():
            if isinstance(entry, Mapping) and "mi" in entry:
                data = dict(entry)
                if "mi_rank" in data and "rank" not in data:
                    data["rank"] = data["mi_rank"]
                agg = validate(MIAggregate, data)
                rel_path = relativize_path(str(file_path), cwd)
                rows.append(
                    RadonResult(
                        scan=scan_row,
                        metric_type="mi",
                        file_path=rel_path or str(file_path),
                        root=root,
                        mi=agg.mi,
                        mi_rank=agg.mi_rank,
                    )
                )

    if isinstance(raw_map, Mapping):
        for file_path, entry in raw_map.items():
            if isinstance(entry, Mapping):
                agg = validate(RawAggregate, entry)
                rel_path = relativize_path(str(file_path), cwd)
                rows.append(
                    RadonResult(
                        scan=scan_row,
                        metric_type="raw",
                        file_path=rel_path or str(file_path),
                        root=root,
                        raw_loc=agg.loc,
                        raw_sloc=agg.sloc,
                        raw_lloc=agg.lloc,
                        raw_comments=agg.comments,
                        raw_multi=agg.multi,
                        raw_blank=agg.blank,
                        raw_single_comments=agg.single_comments,
                    )
                )

    if isinstance(hal_map, Mapping):
        for file_path, entry in hal_map.items():
            payload: Optional[Mapping[str, Any]] = None
            if isinstance(entry, Mapping) and any(
                k.startswith("halstead_") for k in entry.keys()
            ):
                payload = entry
            elif (
                isinstance(entry, Mapping)
                and "total" in entry
                and isinstance(entry["total"], Mapping)
            ):
                payload = entry["total"]
            if not payload:
                continue
            agg = validate(HALAggregate, payload)
            rel_path = relativize_path(str(file_path), cwd)
            rows.append(
                RadonResult(
                    scan=scan_row,
                    metric_type="hal",
                    file_path=rel_path or str(file_path),
                    root=root,
                    hal_volume=agg.halstead_volume,
                    hal_difficulty=agg.halstead_difficulty,
                    hal_effort=agg.halstead_effort,
                    hal_time=agg.halstead_time,
                    hal_bugs=agg.halstead_bugs,
                    extra=None,
                )
            )

    return scan_row, rows


__all__ = [
    "radon_to_models",
]
