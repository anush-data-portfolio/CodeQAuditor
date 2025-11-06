"""Parser for ESLint JavaScript/TypeScript linting results.

ESLint is a popular linter for JavaScript and TypeScript. This parser converts
ESLint's JSON output format into database models.

Functions
---------
eslint_rows_to_models : Parse ESLint JSON output to ORM models

Examples
--------
>>> result = ToolRunResult(parsed_json=[{"messages": []}])
>>> scan, rows = eslint_rows_to_models(result)

See Also
--------
auditor.infra.tools.eslint : ESLint tool wrapper
"""
from __future__ import annotations

import json, re
from pathlib import Path
from typing import Any, List, Mapping, Optional, Tuple, Dict

from ..orm import EslintResult, ScanMetadata
from ._shared import (
    now_iso,
    determine_root_label,
    relativize_path,
    ensure_abs,
    validate,                  # (available for future JSON schema checks)
    strip_before_start_root,
)

# Accept: .ts, .tsx, .js, .jsx, .mjs, .cjs
ACCEPTABLE_EXT = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}

_num_re = re.compile(r"(\d+(?:\.\d+)?)")

def _first_number(text: str) -> Optional[float]:
    m = _num_re.search(text or "")
    return float(m.group(1)) if m else None

def _as_int(x) -> Optional[int]:
    try:
        return int(x) if x is not None else None
    except Exception:
        return None

def _as_bool(x) -> Optional[bool]:
    return None if x is None else bool(x)

def _load_payload(run: Any) -> List[dict]:
    """
    Returns ESLint JSON array from either run.parsed_json or run.stdout (stringified JSON).
    """
    if getattr(run, "parsed_json", None) is not None:
        payload = run.parsed_json
    else:
        stdout = getattr(run, "stdout", "") or ""
        try:
            payload = json.loads(stdout) if stdout.strip() else []
        except json.JSONDecodeError:
            payload = []
    return payload if isinstance(payload, list) else []

def eslint_rows_to_models(
    run: Any,
    radon_bundle: Mapping[str, Any] | None = None,   # kept for symmetry; optional
    *,
    start_root: Optional[str] = None,                # optional trimming like in other parsers
) -> Tuple[ScanMetadata, List[EslintResult]]:
    cwd = getattr(run, "cwd", None)
    
    rows_json: List[dict] = _load_payload(run)


    scan_row = ScanMetadata(scan_timestamp=now_iso())
    out: List[EslintResult] = []
    collected_relpaths: List[str] = []

    total_files = 0
    error_total = warning_total = fix_err_total = fix_warn_total = 0
    by_rule: Dict[str, int] = {}
    by_severity: Dict[str, int] = {"1": 0, "2": 0}

    # complexity-style metrics
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

        file_path_raw = str(file_entry.get("filePath", "") or "")
        ext = Path(file_path_raw).suffix.lower()
        if ext and ext not in ACCEPTABLE_EXT:
            continue

        # Paths via shared helpers
        abs_path = ensure_abs(file_path_raw, cwd)
        abs_path = strip_before_start_root(abs_path, start_root)
    
        rel = relativize_path(file_path_raw, cwd) or file_path_raw
        rel = rel.replace("\\", "/")
        collected_relpaths.append(rel)

        total_files += 1
        err = int(file_entry.get("errorCount", 0) or 0)
        warn = int(file_entry.get("warningCount", 0) or 0)
        fix_err = int(file_entry.get("fixableErrorCount", 0) or 0)
        fix_warn = int(file_entry.get("fixableWarningCount", 0) or 0)

        error_total += err
        warning_total += warn
        fix_err_total += fix_err
        fix_warn_total += fix_warn

        # Per-file rollup row
        # Issues
        for message in file_entry.get("messages") or []:
            if not isinstance(message, dict):
                continue

            rule = message.get("ruleId")
            sev = _as_int(message.get("severity"))  # 1|2
            if rule:
                by_rule[rule] = by_rule.get(rule, 0) + 1
            if sev in (1, 2):
                by_severity[str(sev)] = by_severity.get(str(sev), 0) + 1

            msg_text = (message.get("message") or "").strip()
            num = _first_number(msg_text)

            # tally complexity-like rules
            if rule == "complexity":
                complexity_count += 1
                if num is not None:
                    complexity_max = max(complexity_max, float(num))
            elif rule == "max-depth":
                max_depth_count += 1
                if num is not None:
                    max_depth_max = max(max_depth_max, float(num))
            elif rule == "max-params":
                max_params_count += 1
                if num is not None:
                    max_params_max = max(max_params_max, float(num))
            elif rule == "max-lines-per-function":
                max_lines_count += 1
                if num is not None:
                    max_lines_max = max(max_lines_max, float(num))
            elif rule == "import/no-cycle":
                import_cycle_count += 1

            fix_obj = message.get("fix") or None
            suggestions = message.get("suggestions") or None

            out.append(
                EslintResult(
                    scan=scan_row,
                    row_type="issue",
                    tool="eslint",
                    file_path=abs_path,
                    line_number=_as_int(message.get("line")),
                    end_line_number=_as_int(message.get("endLine")),
                    col_offset=_as_int(message.get("column")),
                    end_col_offset=_as_int(message.get("endColumn")),
                    rule_id=rule,
                    severity=sev,
                    message=msg_text,
                    fatal=_as_bool(message.get("fatal")),
                    fix=_as_bool(fix_obj is not None),
                    node_type=message.get("nodeType"),
                    message_id=message.get("messageId"),
                    suggestion_count=(len(suggestions) if isinstance(suggestions, list) else None),
                    suggestions=suggestions if isinstance(suggestions, list) else None,
                    fix_text=(fix_obj or {}).get("text") if isinstance(fix_obj, dict) else None,
                    fix_range=(fix_obj or {}).get("range") if isinstance(fix_obj, dict) else None,
                )
            )

    # Root label for all rows

    # Assign root for every row (compatible with pydantic-frozen)
    rows_with_root: List[EslintResult] = [] + out
    try:
        for r in rows_with_root:
            r.root = start_root  # type: ignore[attr-defined]
    except Exception:
        rows_with_root = [
            (getattr(r, "model_copy", None) and r.model_copy(update={"root": start_root})) or r  # type: ignore[truthy-bool]
            for r in rows_with_root
        ]

    return scan_row, rows_with_root

__all__ = ["eslint_rows_to_models"]
