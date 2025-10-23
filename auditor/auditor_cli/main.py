#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .scan import export_reports_to_json, scan_workspace


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan one or more repositories and persist normalized findings.",
    )
    parser.add_argument(
        "path",
        type=Path,
        help="Path to a repository or a folder containing multiple repositories.",
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=Path("out/auditor.sqlite3"),
        help="Path to the SQLite database that will store scan results (default: out/auditor.sqlite3).",
    )
    parser.add_argument(
        "--node-prefix",
        type=str,
        default=None,
        help="Override AUDITOR_NODE_PREFIX for Node-based tools.",
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Recursively search for projects underneath the provided path.",
    )
    parser.add_argument(
        "--include-root",
        action="store_true",
        help="Always treat the provided path itself as a project.",
    )
    parser.add_argument(
        "--include-hidden",
        action="store_true",
        help="Include hidden directories (those starting with a dot) when discovering projects.",
    )
    parser.add_argument(
        "--include-all",
        action="store_true",
        help="Treat every discovered directory as a project, regardless of repo markers.",
    )
    parser.add_argument(
        "--store-logs",
        dest="store_logs",
        action="store_true",
        default=True,
        help="Persist stdout/stderr from each tool run into the database (default: enabled).",
    )
    parser.add_argument(
        "--no-store-logs",
        dest="store_logs",
        action="store_false",
        help="Skip storing stdout/stderr blobs in the database.",
    )
    parser.add_argument(
        "--export-json",
        type=Path,
        help="Optional path to write a JSON report containing per-tool findings.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Reduce console output to a minimum.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    verbose = not args.quiet
    collect_findings = args.export_json is not None

    reports = scan_workspace(
        args.path,
        db_path=args.db,
        node_prefix=args.node_prefix,
        include_root=args.include_root,
        recursive=args.recursive,
        include_hidden=args.include_hidden,
        include_all=args.include_all,
        store_logs=args.store_logs,
        verbose=verbose,
        collect_findings=collect_findings,
    )

    if collect_findings and args.export_json is not None:
        export_reports_to_json(reports, args.export_json)
        if verbose:
            print(f"\nJSON report written to {args.export_json}")

    if verbose:
        print("\nScan complete.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
