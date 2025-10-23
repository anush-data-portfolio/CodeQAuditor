"""
Example driver that scans a single repository using the default tool suite.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from auditor.auditor_cli.scan import build_default_tools, scan_repository
from auditor.storage import AuditDatabase


def main() -> None:
    os.environ.setdefault("AUDITOR_NODE_PREFIX", "/abs/path/to/CodeQAuditor")

    repo = Path("pits")
    tools = build_default_tools()

    db_path = Path("out/auditor.sqlite3")
    db_path.parent.mkdir(parents=True, exist_ok=True)

    db = AuditDatabase(str(db_path))
    try:
        report = scan_repository(
            repo,
            db,
            tools,
            store_logs=True,
            collect_findings=True,
            verbose=True,
        )
    finally:
        db.close()

    findings_by_tool = report.findings_by_tool or {}

    json_data = []
    for tool in tools:
        tool_findings = findings_by_tool.get(tool.name, [])
        json_data.append([finding.to_dict() for finding in tool_findings])

    output_path = Path("out/audit_results.json")
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(json_data, handle, indent=2)

    print("\nScan complete. Findings written to out/audit_results.json")


if __name__ == "__main__":
    main()
