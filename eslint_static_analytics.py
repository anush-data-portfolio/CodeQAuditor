"""
Static ESLint analytics tool
============================

This module provides a small Python wrapper around ESLint.  It is designed
to collect linting data for multiple JavaScript/TypeScript projects without
installing any additional dependencies into those projects.  Instead, it
assumes that ESLint (and any required plugins/configurations) are installed
once in the directory where this script resides.  Each project you wish to
analyse can live anywhere on disk – the current working directory used when
invoking ESLint is changed accordingly, so the tool never pollutes the
target projects with `node_modules`.

The tool supports generating JSON reports, optionally including rule
metadata and statistics.  It also supports turning off a set of rules via
CLI flags.  The JSON data can be used to further analyse code quality,
complexity, security issues or other custom metrics.

Key features
------------

* Runs ESLint in the context of each project directory.
* Supports common ESLint CLI flags such as:
  * `--format` to produce machine‑readable JSON output.  According to the
    ESLint documentation, using `--format json` will output
    JSON‑serialised results, which is useful when you want to
    programmatically work with the CLI's linting results【181270205346362†L2316-L2329】.
    Alternatively `json-with-metadata` can be used to include rule metadata
    alongside the results【529452607612238†L203-L209】.
  * `--stats` to include statistics in the output.  The `--stats`
    option is intended for use with custom formatters and can also be
    used with the built‑in `json` formatter【181270205346362†L3643-L3676】.
  * `--ext` to add file extensions beyond the default set.  ESLint
    normally lints `.js`, `.mjs` and `.cjs` files as well as any
    extensions specified in the configuration file.  The `--ext`
    flag allows you to specify additional extensions【181270205346362†L912-L919】.
  * `--no-error-on-unmatched-pattern` to prevent errors when a quoted
    glob pattern or `--ext` argument doesn’t match any files【181270205346362†L3287-L3294】.
  * `--config` to point to a custom ESLint configuration file【181270205346362†L741-L756】.
  * `--max-warnings` to specify a warning threshold, causing ESLint
    to exit with a non‑zero status if the number of warnings exceeds the
    threshold【181270205346362†L2210-L2222】.
  * `--rule` to enable or disable rules via the command line
    (e.g. turning off unresolved import rules)【181270205346362†L1413-L1424】.
  * `--resolve-plugins-relative-to` to direct ESLint to look for
    plugins relative to this script rather than the project being
    analysed.  The documentation notes that when a config file lives
    outside the current project or when an integration installs plugins on
    behalf of the user, this flag should point to the top‑level
    directory of the tool【181270205346362†L1276-L1294】.

Because this script calls ESLint via a subprocess, you must have a
working `eslint` binary in your `PATH` or in a local `node_modules/.bin`
directory.  Running ESLint with `npx` is also supported, but any
network‑dependent installations must be preinstalled in the environment
where this script runs.

"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

################################################################################
# Data classes
################################################################################


@dataclass
class ESLintRunResult:
    """Stores the results of a single ESLint run.

    Attributes:
        project_path: Path to the project that was linted.
        eslint_cmd: The full command line that was executed.
        raw_output: Raw JSON output from ESLint (as parsed into Python types).
        stats: A dictionary summarising error/warning counts and rule counts.
        output_file: Optional path to the file where the JSON report was saved.
    """

    project_path: Path
    eslint_cmd: List[str]
    raw_output: Any
    stats: Dict[str, Any] = field(default_factory=dict)
    output_file: Optional[Path] = None


################################################################################
# Helper functions
################################################################################


def build_eslint_command(
    project_path: Path,
    *,
    node_modules_root: Optional[Path] = None,
    exts: Sequence[str] = (".ts", ".tsx", ".js", ".jsx"),
    config_path: Optional[Path] = None,
    max_warnings: Optional[int] = None,
    extra_args: Optional[Sequence[str]] = None,
    suppress_rules: Optional[Iterable[str]] = None,
    include_stats: bool = True,
    format_name: str = "json-with-metadata",
) -> List[str]:
    """Construct the ESLint command for a given project.

    The command will always include the `--format` flag set to the provided
    formatter name.  If ``include_stats`` is True, the ``--stats`` flag is
    added.  The ``--ext`` flag is used to include additional file
    extensions; by default ESLint only lints `.js`, `.mjs` and `.cjs`
    files, so common TypeScript and JSX/TSX extensions are added here
    according to the ESLint documentation【181270205346362†L912-L919】.

    A list of rules may be suppressed by passing them via the ``--rule``
    CLI option with a severity of ``off``【181270205346362†L1413-L1424】.

    If a ``node_modules_root`` is provided, the command will add the
    ``--resolve-plugins-relative-to`` flag pointing to that directory to
    ensure that plugins installed with this tool are discovered【181270205346362†L1276-L1294】.

    Returns:
        A list of strings representing the command to execute.
    """
    # Base command: prefer local installation in node_modules/.bin, else rely on global
    bin_path_candidates: List[str] = []
    # local node_modules/.bin relative to this script
    local_bin = Path(__file__).resolve().parent / "node_modules" / ".bin" / "eslint"
    if local_bin.exists():
        bin_path_candidates.append(str(local_bin))
    # fallback to bare eslint (expect it to be on PATH)
    bin_path_candidates.append("eslint")
    # fallback to npx invocation
    bin_path_candidates.append("npx")
    bin_path_candidates.append("eslint")
    # Flatten into command: if using npx, we will have two elements, else one
    eslint_cmd: List[str]
    if (
        len(bin_path_candidates) >= 3
        and bin_path_candidates[0] != "eslint"
        and not local_bin.exists()
    ):
        # Use npx eslint
        eslint_cmd = ["npx", "eslint"]
    else:
        eslint_cmd = (
            [bin_path_candidates[0]]
            if bin_path_candidates[0] != "eslint"
            else ["eslint"]
        )
    # Format flag
    cmd = eslint_cmd + ["--format", format_name]
    if include_stats:
        cmd.append("--stats")
    # Prevent errors on unmatched glob patterns (e.g. when no files match)
    cmd.append("--no-error-on-unmatched-pattern")
    # Provide additional file extensions
    for ext in exts:
        # CLI accepts repeated --ext flags or a comma separated list
        cmd.extend(["--ext", ext])
    # Supply config file if provided
    if config_path:
        cmd.extend(["--config", str(config_path)])
    # Set max warnings if provided
    if max_warnings is not None:
        cmd.extend(["--max-warnings", str(max_warnings)])
    # Suppress specific rules by turning them off
    if suppress_rules:
        for rule in suppress_rules:
            cmd.extend(["--rule", f"{rule}:off"])
    # Ensure ESLint resolves plugins relative to our tool root
    if node_modules_root:
        cmd.extend(["--resolve-plugins-relative-to", str(node_modules_root)])
    # Additional user arguments
    if extra_args:
        cmd.extend(list(extra_args))
    # Patterns to lint – use glob patterns across the project directory
    # We use recursive globs for each extension (e.g. **/*.js).  Quoting the
    # pattern here avoids the shell expansion; ESLint performs its own globbing.
    for ext in exts:
        suffix = ext if ext.startswith(".") else f".{ext}"
        cmd.append(f'"**/*{suffix}"')
    return cmd


def run_eslint(
    project_path: Path,
    *,
    node_modules_root: Optional[Path] = None,
    exts: Sequence[str] = (".ts", ".tsx", ".js", ".jsx"),
    config_path: Optional[Path] = None,
    max_warnings: Optional[int] = None,
    extra_args: Optional[Sequence[str]] = None,
    suppress_rules: Optional[Iterable[str]] = None,
    include_stats: bool = True,
    format_name: str = "json-with-metadata",
    output_file: Optional[Path] = None,
) -> ESLintRunResult:
    """Run ESLint on the given project and return an ESLintRunResult.

    This function constructs the ESLint command using
    :func:`build_eslint_command`, executes it in a subprocess and parses the
    output as JSON.  The raw linting results are stored along with a basic
    summary of error and warning counts per file and overall.

    Args:
        project_path: Path to the directory to lint.
        node_modules_root: Root directory of the tool’s node_modules.  Used
            for resolving plugins.
        exts: Sequence of file extensions to include.
        config_path: Path to an ESLint configuration file.
        max_warnings: Maximum warnings threshold.
        extra_args: Additional CLI arguments for ESLint.
        suppress_rules: Iterable of rule IDs to disable for this run.
        include_stats: Whether to include statistics via the `--stats` flag.
        format_name: Formatter name (e.g. ``json`` or ``json-with-metadata``).
        output_file: Optional file path to write the JSON report to.

    Returns:
        An instance of :class:`ESLintRunResult` with parsed results and summary.

    Raises:
        subprocess.CalledProcessError: If ESLint exits with a non-zero status
            (other than the warning threshold) and no JSON output is produced.
    """
    project_path = project_path.resolve()
    # Build command line
    cmd = build_eslint_command(
        project_path,
        node_modules_root=node_modules_root,
        exts=exts,
        config_path=config_path,
        max_warnings=max_warnings,
        extra_args=extra_args,
        suppress_rules=suppress_rules,
        include_stats=include_stats,
        format_name=format_name,
    )
    # Execute ESLint
    result = subprocess.run(
        cmd,
        cwd=str(project_path),
        capture_output=True,
        text=True,
        shell=False,
    )
    # ESLint outputs the linting report on stdout.  On errors, it may still
    # produce JSON, but we ignore the exit code here because the exit code
    # reflects lint failures (non‑zero if any errors or if max warnings is
    # exceeded).  We only propagate failures where no output was produced.
    stdout = result.stdout.strip()
    if not stdout:
        # If there is no output, something went wrong.  Raise an exception
        result.check_returncode()
    # Attempt to parse JSON.  ESLint outputs plain JSON or an array.  When
    # using the `json-with-metadata` formatter, the data is an object with
    # `results` and `metadata` keys【529452607612238†L203-L209】.
    try:
        lint_data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Failed to parse ESLint output as JSON for project {project_path}: {exc}\nOutput:\n{stdout}"
        ) from exc
    # Optionally write the raw JSON to file
    if output_file:
        output_file = output_file.resolve()
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with output_file.open("w", encoding="utf-8") as f:
            json.dump(lint_data, f, indent=2)
    # Compute summary statistics
    stats = compute_summary(lint_data)
    return ESLintRunResult(
        project_path=project_path,
        eslint_cmd=cmd,
        raw_output=lint_data,
        stats=stats,
        output_file=output_file,
    )


def compute_summary(lint_data: Any) -> Dict[str, Any]:
    """Compute a summary of ESLint results.

    The summary collects total counts of errors, warnings and fixable issues.
    It also aggregates counts per rule ID.

    The function accepts either a list of result objects (as returned
    by the `json` formatter) or an object with a `results` property (as
    returned by the `json-with-metadata` formatter)【529452607612238†L203-L209】.

    Returns:
        A dictionary with overall and per-rule statistics.
    """
    # Normalise data to a list of result objects
    if isinstance(lint_data, dict) and "results" in lint_data:
        results = lint_data.get("results", [])
    elif isinstance(lint_data, list):
        results = lint_data
    else:
        return {}
    total_errors = 0
    total_warnings = 0
    total_fixable = 0
    rule_counts: Dict[str, Dict[str, int]] = {}
    for entry in results:
        errors = entry.get("errorCount", 0)
        warnings = entry.get("warningCount", 0)
        fixable = entry.get("fixableErrorCount", 0) + entry.get(
            "fixableWarningCount", 0
        )
        total_errors += errors
        total_warnings += warnings
        total_fixable += fixable
        for msg in entry.get("messages", []):
            rule_id = msg.get("ruleId") or "<unknown>"
            severity = msg.get("severity", 0)
            if rule_id not in rule_counts:
                rule_counts[rule_id] = {"errors": 0, "warnings": 0}
            if severity == 2:
                rule_counts[rule_id]["errors"] += 1
            elif severity == 1:
                rule_counts[rule_id]["warnings"] += 1
    return {
        "total_errors": total_errors,
        "total_warnings": total_warnings,
        "total_fixable": total_fixable,
        "per_rule": rule_counts,
    }


def analyse_projects(
    projects: Sequence[Path],
    *,
    node_modules_root: Optional[Path] = None,
    exts: Sequence[str] = (".ts", ".tsx", ".js", ".jsx"),
    config_path: Optional[Path] = None,
    max_warnings: Optional[int] = None,
    extra_args: Optional[Sequence[str]] = None,
    suppress_rules: Optional[Iterable[str]] = None,
    include_stats: bool = True,
    format_name: str = "json-with-metadata",
    output_dir: Optional[Path] = None,
) -> List[ESLintRunResult]:
    """Run ESLint on a collection of project directories.

    This convenience function simply loops over the given projects and
    calls :func:`run_eslint` for each one.  If ``output_dir`` is given,
    each report will be written into that directory with the project
    directory name (or last path component) as the file name.

    Returns:
        A list of :class:`ESLintRunResult` objects containing the raw results
        and summary statistics for each project.
    """
    results: List[ESLintRunResult] = []
    for project_path in projects:
        project_path = project_path.resolve()
        # Determine report file path if required
        report_file: Optional[Path] = None
        if output_dir:
            safe_name = project_path.name.replace(os.sep, "_")
            report_file = output_dir / f"eslint_report_{safe_name}.json"
        res = run_eslint(
            project_path,
            node_modules_root=node_modules_root,
            exts=exts,
            config_path=config_path,
            max_warnings=max_warnings,
            extra_args=extra_args,
            suppress_rules=suppress_rules,
            include_stats=include_stats,
            format_name=format_name,
            output_file=report_file,
        )
        results.append(res)
    return results


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Simple command-line entry point.

    You can invoke this script from the command line to lint one or more
    projects.  Examples:

        python eslint_static_analytics.py /path/to/project1 /path/to/project2 \
            --output-dir reports

    For a list of options, run ``python eslint_static_analytics.py --help``.
    """
    import argparse

    parser = argparse.ArgumentParser(
        description="Run ESLint on multiple projects and produce JSON analytics reports."
    )
    parser.add_argument(
        "projects", nargs="+", help="Paths to project directories to lint."
    )
    parser.add_argument(
        "--ext",
        dest="exts",
        action="append",
        default=[],
        help="Additional file extensions to lint (repeatable).",
    )
    parser.add_argument(
        "-c", "--config", dest="config", help="Path to an ESLint configuration file."
    )
    parser.add_argument(
        "--max-warnings",
        dest="max_warnings",
        type=int,
        default=None,
        help="Maximum number of warnings allowed before ESLint exits with an error.",
    )
    parser.add_argument(
        "--extra-arg",
        dest="extra_args",
        action="append",
        default=[],
        help="Extra arguments to pass to ESLint (repeatable).",
    )
    parser.add_argument(
        "--suppress-rule",
        dest="suppress_rules",
        action="append",
        default=[],
        help="Rules to disable (repeatable).",
    )
    parser.add_argument(
        "--no-stats",
        dest="include_stats",
        action="store_false",
        help="Do not include --stats flag when running ESLint.",
    )
    parser.add_argument(
        "--format",
        dest="format_name",
        default="json-with-metadata",
        help="Name of the ESLint formatter to use (default: json-with-metadata).",
    )
    parser.add_argument(
        "--output-dir",
        dest="output_dir",
        help="Directory in which to save JSON reports.",
    )
    parser.add_argument(
        "--plugins-root",
        dest="plugins_root",
        help="Path to directory where ESLint plugins are installed (used with --resolve-plugins-relative-to).",
    )
    args = parser.parse_args(argv)

    exts = args.exts if args.exts else [".ts", ".tsx", ".js", ".jsx"]
    projects = [Path(p) for p in args.projects]
    config_path = Path(args.config).resolve() if args.config else None
    output_dir = Path(args.output_dir).resolve() if args.output_dir else None
    plugins_root = Path(args.plugins_root).resolve() if args.plugins_root else None
    res = analyse_projects(
        projects,
        node_modules_root=plugins_root,
        exts=exts,
        config_path=config_path,
        max_warnings=args.max_warnings,
        extra_args=args.extra_args,
        suppress_rules=args.suppress_rules,
        include_stats=args.include_stats,
        format_name=args.format_name,
        output_dir=output_dir,
    )
    # Print a summary report
    for r in res:
        print(f"Project: {r.project_path}")
        print(f"  Command: {' '.join(r.eslint_cmd)}")
        print(
            f"  Errors: {r.stats.get('total_errors')}, Warnings: {r.stats.get('total_warnings')}, Fixable: {r.stats.get('total_fixable')}"
        )
        print(f"  Report saved to: {r.output_file if r.output_file else 'N/A'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
