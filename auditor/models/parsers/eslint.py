from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, List, Mapping, Optional, Tuple

from ..orm import EslintResult, ScanMetadata


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_payload(run: Any) -> Iterable[dict]:
    if getattr(run, "parsed_json", None) is not None:
        payload = run.parsed_json
    else:
        stdout = getattr(run, "stdout", "") or ""
        try:
            payload = json.loads(stdout) if stdout.strip() else []
        except json.JSONDecodeError:
            payload = []
    return payload if isinstance(payload, list) else []


def _root_parts(cwd: str | None) -> Tuple[str, Path]:
    base = Path(cwd) if cwd else Path.cwd()
    if not base.is_absolute():
        base = (Path.cwd() / base).resolve()
    label = base.name or str(base)
    return label, base


def _rel_with_root(path: str, cwd: Path, root_label: str) -> Tuple[str, str]:
    if not path:
        return root_label, "."
    candidate = Path(path)
    try:
        if not candidate.is_absolute():
            candidate = (cwd / candidate).resolve()
        rel = str(candidate.relative_to(cwd))
    except Exception:
        rel = path
    rel = rel.replace("\\", "/").rstrip("/")
    if rel in {"", "."}:
        return root_label, "."
    return f"{root_label}/{rel}", rel


def _first_number(text: str) -> Optional[float]:
    if not text:
        return None
    match = re.search(r"(\d+(?:\.\d+)?)", text)
    if not match:
        return None
    try:
        return float(match.group(1))
    except Exception:
        return None


def _first_if_tuple(value):
    return value[0] if isinstance(value, tuple) and value else value


def _apply_radon_summary(
    scan_row_obj: EslintResult, radon_bundle: Mapping[str, Any] | None
) -> None:
    if not radon_bundle:
        return

    mi_map = _first_if_tuple(radon_bundle.get("mi", {})) or {}
    hal_map = _first_if_tuple(radon_bundle.get("hal", {})) or {}

    mi_vals: List[float] = []
    if isinstance(mi_map, Mapping):
        for entry in mi_map.values():
            if isinstance(entry, Mapping) and isinstance(entry.get("mi"), (int, float)):
                mi_vals.append(float(entry["mi"]))
    if mi_vals:
        scan_row_obj.mi_min = min(mi_vals)
        scan_row_obj.mi_max = max(mi_vals)
        scan_row_obj.mi_avg = sum(mi_vals) / len(mi_vals)

    volume_total = effort_total = bugs_total = 0.0
    if isinstance(hal_map, Mapping):
        for entry in hal_map.values():
            payload: Optional[Mapping[str, Any]] = None
            if (
                isinstance(entry, Mapping)
                and "total" in entry
                and isinstance(entry["total"], Mapping)
            ):
                payload = entry["total"]
            elif isinstance(entry, Mapping):
                payload = entry
            if not payload:
                continue
            volume_total += float(payload.get("volume") or payload.get("halstead_volume") or 0)  # type: ignore[arg-type]
            effort_total += float(payload.get("effort") or payload.get("halstead_effort") or 0)  # type: ignore[arg-type]
            bugs_total += float(payload.get("bugs") or payload.get("halstead_bugs") or 0)  # type: ignore[arg-type]
    if any(val for val in (volume_total, effort_total, bugs_total)):
        scan_row_obj.hal_volume_total = volume_total or None
        scan_row_obj.hal_effort_total = effort_total or None
        scan_row_obj.hal_bugs_total = bugs_total or None


def eslint_rows_to_models(
    run: Any,
    radon_bundle: Mapping[str, Any] | None = None,
) -> Tuple[ScanMetadata, List[EslintResult]]:
    rows_json = _load_payload(run)
    root_label, cwd_path = _root_parts(getattr(run, "cwd", None))

    scan_row = ScanMetadata(scan_timestamp=_now_iso())
    out: List[EslintResult] = []

    total_files = 0
    error_total = warning_total = fix_err_total = fix_warn_total = 0
    rule_counts: dict[str, int] = {}

    complexity_count = 0
    complexity_max = 0.0
    max_depth_count = 0
    max_depth_max = 0.0
    max_params_count = 0
    max_params_max = 0.0
    max_lines_count = 0
    max_lines_max = 0.0
    import_cycle_count = 0

    for file_entry in rows_json:
        if not isinstance(file_entry, dict):
            continue
        total_files += 1
        error_total += int(file_entry.get("errorCount", 0) or 0)
        warning_total += int(file_entry.get("warningCount", 0) or 0)
        fix_err_total += int(file_entry.get("fixableErrorCount", 0) or 0)
        fix_warn_total += int(file_entry.get("fixableWarningCount", 0) or 0)

        norm_path, rel = _rel_with_root(
            str(file_entry.get("filePath", "")), cwd_path, root_label
        )

        out.append(
            EslintResult(
                scan=scan_row,
                row_type="file",
                tool="eslint",
                file_path=norm_path,
                root=root_label,
                relpath=rel,
                line_number=None,
                end_line_number=None,
                col_offset=None,
                end_col_offset=None,
                error_count=int(file_entry.get("errorCount", 0) or 0),
                warning_count=int(file_entry.get("warningCount", 0) or 0),
                fixable_error_count=int(file_entry.get("fixableErrorCount", 0) or 0),
                fixable_warning_count=int(
                    file_entry.get("fixableWarningCount", 0) or 0
                ),
            )
        )

        for message in file_entry.get("messages") or []:
            if not isinstance(message, dict):
                continue
            rule = message.get("ruleId")
            if rule:
                rule_counts[rule] = rule_counts.get(rule, 0) + 1

            msg_text = str(message.get("message", "")).strip()
            val = _first_number(msg_text)
            if rule == "complexity":
                complexity_count += 1
                if val is not None:
                    complexity_max = max(complexity_max, float(val))
            elif rule == "max-depth":
                max_depth_count += 1
                if val is not None:
                    max_depth_max = max(max_depth_max, float(val))
            elif rule == "max-params":
                max_params_count += 1
                if val is not None:
                    max_params_max = max(max_params_max, float(val))
            elif rule == "max-lines-per-function":
                max_lines_count += 1
                if val is not None:
                    max_lines_max = max(max_lines_max, float(val))
            elif rule == "import/no-cycle":
                import_cycle_count += 1

            out.append(
                EslintResult(
                    scan=scan_row,
                    row_type="issue",
                    tool="eslint",
                    file_path=norm_path,
                    root=root_label,
                    relpath=rel,
                    line_number=message.get("line"),
                    end_line_number=message.get("endLine"),
                    col_offset=message.get("column"),
                    end_col_offset=message.get("endColumn"),
                    rule_id=rule,
                    severity=message.get("severity"),
                    message=msg_text,
                    fatal=bool(message.get("fatal", False)),
                    fix=bool(message.get("fix")),
                )
            )

    scan_summary = EslintResult(
        scan=scan_row,
        row_type="scan",
        tool="eslint",
        file_path=root_label,
        root=root_label,
        relpath=None,
        line_number=None,
        end_line_number=None,
        col_offset=None,
        end_col_offset=None,
        file_count=total_files,
        error_count=error_total,
        warning_count=warning_total,
        fixable_error_count=fix_err_total,
        fixable_warning_count=fix_warn_total,
        rule_counts=dict(sorted(rule_counts.items(), key=lambda kv: (-kv[1], kv[0]))),
        duration_s=getattr(run, "duration_s", None),
        cmd=getattr(run, "cmd", None),
        cwd=str(cwd_path),
        returncode=getattr(run, "exitcode", getattr(run, "returncode", None)),
        complexity_count=complexity_count or None,
        complexity_max=complexity_max or None,
        max_depth_count=max_depth_count or None,
        max_depth_max=max_depth_max or None,
        max_params_count=max_params_count or None,
        max_params_max=max_params_max or None,
        max_lines_func_count=max_lines_count or None,
        max_lines_func_max=max_lines_max or None,
        import_cycle_count=import_cycle_count or None,
    )

    _apply_radon_summary(scan_summary, radon_bundle)

    out.insert(0, scan_summary)
    return scan_row, out


__all__ = ["eslint_rows_to_models"]
