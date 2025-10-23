"""
Repo Auditor Dashboard (reworked for extended findings schema)

This Dash application expands upon the original auditor dashboard by making
use of additional columns in the ``findings`` table (kind, category,
metrics_json, tags) and by dropping the severity‑driven views in favour
of distribution plots by tool, by category and by file.  It also parses
``metrics_json`` to extract cyclomatic complexity (and related metrics)
and exposes a dedicated "Complexity" tab where developers can inspect
and drill into maintainability metrics.  A KPI for critical gitleaks
findings replaces the old High/Critical severity KPI.

Run:

  pip install dash dash-bootstrap-components dash-ag-grid dash-mantine-components pandas plotly
  export AUDITOR_DB=/absolute/path/to/auditor.sqlite3   # or set in the UI
  python app_rework.py

The app assumes a SQLite database with two tables ``scans`` and
``findings`` (see SCHEMA in the problem statement).  The ``findings``
table may contain JSON strings in ``extra_json`` and ``metrics_json``.  The
``metrics_json`` field is parsed to extract cyclomatic complexity and
other maintainability metrics where present.
"""

import os
import os.path as op
import re
import sqlite3
import json
from typing import List, Dict, Any
from io import StringIO

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

import dash
from dash import Dash, dcc, html, Input, Output, State, ctx, no_update
import dash_bootstrap_components as dbc
import dash_ag_grid as dag
import dash_mantine_components as dmc

# ---------- Config ----------
# Default DB path is taken from environment if provided; otherwise
# fallback to a reasonable default.  You can override it at runtime via
# the DB loader input.
DEFAULT_DB = os.environ.get("AUDITOR_DB", "auditor.sqlite3")

# Map languages to file extensions.  This helps the tabs filter down
# findings to those relevant for a given language.
LANG_EXT = {
    "Python": [".py"],
    "TypeScript": [".ts"],
    "TSX": [".tsx"],
    "JavaScript": [".js"],
}

# We no longer care about severity buckets for most visualisations but
# keep this list for the Tool Details tab.
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]


# ---------- Helpers ----------
def _normalize_path(p: str) -> str:
    """Normalise path separators and strip leading/trailing slashes."""
    if pd.isna(p) or not str(p).strip():
        return ""
    p = str(p).replace("\\\\", "/").replace("\\", "/")
    p = re.sub("/{2,}", "/", p)
    return p.strip("/")


def _relative_file_path(file_path: str, repo_path: str) -> str:
    """Return file_path relative to repo_path (both normalised)."""
    f = _normalize_path(file_path)
    r = _normalize_path(repo_path)
    if r and f.startswith(r):
        f = f[len(r) :].lstrip("/")
    return f


def _file_ext_match(p: str, exts: List[str]) -> bool:
    """Return True if path p ends with one of the provided extensions."""
    p = (p or "").lower()
    return any(p.endswith(e.lower()) for e in exts)


def parse_metrics_json(metrics_json_str: str) -> float:
    """Parse metrics_json string and return a cyclomatic complexity value.

    The metrics_json field can contain arbitrary JSON depending on the
    tool.  This helper searches recursively for keys such as
    ``cyclomatic_complexity``, ``cyclomatic`` or ``complexity`` and
    returns the first numeric value encountered.  If parsing fails or
    the keys are absent, returns None.
    """
    if not metrics_json_str or pd.isna(metrics_json_str):
        return None
    try:
        data = json.loads(metrics_json_str)
    except Exception:
        return None

    def find_complexity(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                key = str(k).lower()
                # Accept various names for complexity metrics
                if key in {"cyclomatic_complexity", "cyclomatic", "complexity"}:
                    # Cast to float if possible
                    try:
                        return float(v)
                    except Exception:
                        return None
                # Otherwise search nested
                res = find_complexity(v)
                if res is not None:
                    return res
        elif isinstance(obj, list):
            for item in obj:
                res = find_complexity(item)
                if res is not None:
                    return res
        return None

    return find_complexity(data)


def parse_tags(tags_str: str) -> List[str]:
    """Normalise the tags field into a list of strings."""
    if not tags_str or pd.isna(tags_str):
        return []
    # Try JSON first
    try:
        obj = json.loads(tags_str)
        if isinstance(obj, list):
            return [str(x).strip() for x in obj if str(x).strip()]
    except Exception:
        pass
    # Otherwise split comma separated
    return [t.strip() for t in str(tags_str).split(",") if t.strip()]


def load_df(db_path: str) -> tuple[pd.DataFrame, str]:
    """Load joined findings and scans from SQLite and return DataFrame and status.

    The function selects additional columns from the findings table and
    normalises file paths and severity.  It also parses ``metrics_json``
    into a ``complexity`` column and parses ``tags`` into a list.
    """
    if not op.exists(db_path):
        # Return empty DataFrame with expected columns
        cols = [
            "id",
            "tool",
            "name",
            "rule_id",
            "severity",
            "message",
            "file",
            "line",
            "col",
            "end_line",
            "end_col",
            "fingerprint",
            "extra_json",
            "kind",
            "category",
            "metrics_json",
            "tags",
            "repo_path",
            "started_at",
            "finished_at",
        ]
        empty = pd.DataFrame(columns=cols)
        return empty, f"❌ DB not found: {op.abspath(db_path)}"

    with sqlite3.connect(db_path) as conn:
        # Verify required tables exist
        tables = pd.read_sql("SELECT name FROM sqlite_master WHERE type='table'", conn)[
            "name"
        ].tolist()
        has_findings = "findings" in tables
        has_scans = "scans" in tables
        if not (has_findings and has_scans):
            cols = [
                "id",
                "tool",
                "name",
                "rule_id",
                "severity",
                "message",
                "file",
                "line",
                "col",
                "end_line",
                "end_col",
                "fingerprint",
                "extra_json",
                "kind",
                "category",
                "metrics_json",
                "tags",
                "repo_path",
                "started_at",
                "finished_at",
            ]
            empty = pd.DataFrame(columns=cols)
            return empty, f"❌ Required tables missing. Found: {tables}"

        # Row counts for status
        counts = (
            pd.read_sql(
                """
            SELECT
              (SELECT COUNT(*) FROM scans)    AS scans_rows,
              (SELECT COUNT(*) FROM findings) AS findings_rows
        """,
                conn,
            )
            .iloc[0]
            .to_dict()
        )

        # Load joined data with extended columns
        df = pd.read_sql(
            """
            SELECT f.id, f.tool, f.name, f.rule_id, f.severity, f.message, f.file,
                   f.line, f.col, f.end_line, f.end_col, f.fingerprint, f.extra_json,
                   f.kind, f.category, f.metrics_json, f.tags,
                   s.repo_path, s.started_at, s.finished_at
            FROM findings f
            JOIN scans s ON f.scan_id = s.id
            """,
            conn,
            parse_dates=["started_at", "finished_at"],
        )

    # Normalise path and derive relative path
    df["repo_path"] = df.get("repo_path", pd.Series([], dtype="object")).fillna("")
    df["file"] = df.get("file", pd.Series([], dtype="object")).fillna("")
    df["rel_file"] = [
        _relative_file_path(f, r) for f, r in zip(df["file"], df["repo_path"])
    ]
    # Derive directories and top level for tree navigation
    df["dir"] = df["rel_file"].apply(
        lambda p: "/".join(p.split("/")[:-1]) if "/" in (p or "") else "(root)"
    )
    df["top_level"] = df["rel_file"].apply(
        lambda p: (p.split("/")[0] if "/" in (p or "") else "(root)") if p else "(root)"
    )

    # Normalise severity
    df["severity"] = (
        df.get("severity", pd.Series([], dtype="object"))
        .fillna("UNKNOWN")
        .astype(str)
        .str.upper()
    )

    # Parse metrics_json into a complexity metric (float) and parse tags
    df["complexity"] = df.get("metrics_json", pd.Series([], dtype="object")).apply(
        parse_metrics_json
    )
    df["tags_parsed"] = df.get("tags", pd.Series([], dtype="object")).apply(parse_tags)

    status = (
        f"✅ Loaded {len(df):,} joined rows from: {op.abspath(db_path)} · "
        f"tables={tables} · counts={counts}"
    )
    return df, status


def build_tree_data(paths: List[str]) -> List[Dict[str, Any]]:
    """Construct tree data structure for the folder tree component.

    Given a list of relative file paths, build a nested dictionary of
    folders and return the format expected by the Mantine Tree component.
    """
    tree: Dict[str, Any] = {}
    for p in paths:
        if not p:
            continue
        parts = [part for part in p.split("/") if part]
        folders = parts[:-1] if len(parts) > 1 else ["(root)"]
        cur = tree
        acc = ""
        for folder in folders:
            acc = f"{acc}/{folder}" if acc else folder
            cur = cur.setdefault(folder, {"__key__": acc, "__children__": {}})[
                "__children__"
            ]
        if len(parts) == 1:
            cur.setdefault("(root)", {"__key__": "(root)", "__children__": {}})

    def to_list(d: Dict[str, Any]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for name in sorted(d.keys(), key=lambda s: s.lower()):
            node = d[name]
            children = node.get("__children__", {})
            obj = {"label": name, "value": node.get("__key__", name)}
            if children:
                obj["children"] = to_list(children)
            out.append(obj)
        return out

    return [{"label": "All", "value": "__ALL__", "children": to_list(tree)}]


def filter_df(
    df: pd.DataFrame, language: str, folder_value: str, text_query: str
) -> pd.DataFrame:
    """Filter DataFrame by language extension, folder selection and search query.

    Severity filtering has been removed because severities are not useful
    in most contexts; the query is matched against tool, rule_id, name,
    message and rel_file.
    """
    if df is None or df.empty:
        return df
    exts = LANG_EXT.get(language, [])
    mask = df["rel_file"].apply(lambda p: _file_ext_match(p, exts))
    if folder_value and folder_value != "__ALL__":
        fv = folder_value.strip("/")
        if fv == "(root)":
            mask &= ~df["rel_file"].str.contains("/", na=False)
        else:
            mask &= df["rel_file"].str.startswith(fv + "/", na=False)
    if text_query:
        tq = text_query.lower()
        mask &= (
            df["message"].astype(str).str.lower().str.contains(tq, na=False)
            | df["name"].astype(str).str.lower().str.contains(tq, na=False)
            | df["rule_id"].astype(str).str.lower().str.contains(tq, na=False)
            | df["rel_file"].astype(str).str.lower().str.contains(tq, na=False)
            | df["tool"].astype(str).str.lower().str.contains(tq, na=False)
            | df["kind"].astype(str).str.lower().str.contains(tq, na=False)
            | df["category"].astype(str).str.lower().str.contains(tq, na=False)
        )
    return df[mask].copy()


# ---------- App ----------
# Initialise Dash with a bootstrap theme and Mantine provider.  The
# Mantine provider enables the dash-mantine-components to function
# correctly (for example, the Tree component used in the left sidebar).
app = Dash(
    __name__,
    external_stylesheets=[dbc.themes.FLATLY],
    suppress_callback_exceptions=True,
    title="Repo Auditor Dashboard (Rework)",
)


def kpi_card(title: str, id_value: str) -> dbc.Card:
    """Return a KPI card with a title and dynamic value."""
    return dbc.Card(
        dbc.CardBody(
            [
                html.Div(title, className="kpi-title"),
                html.H2("—", id=id_value, className="kpi-value"),
            ]
        ),
        className="shadow-sm kpi-card",
    )


# Layout
app.layout = dmc.MantineProvider(
    withGlobalClasses=True,
    withCssVariables=True,
    children=[
        dbc.Container(
            fluid=True,
            children=[
                dcc.Store(id="store-raw"),
                dcc.Store(id="store-tree"),
                dcc.Store(id="store-filtered"),
                # Header
                dbc.Row(
                    [
                        dbc.Col(
                            [
                                html.H2(
                                    "Repo Auditor Dashboard", className="mt-3 mb-0"
                                ),
                                html.Div(
                                    "Explore issues by language, folder and search",
                                    className="text-muted mb-2",
                                ),
                                dcc.Tabs(
                                    id="lang-tabs",
                                    value="Python",
                                    children=[
                                        dcc.Tab(label="Python", value="Python"),
                                        dcc.Tab(label="TypeScript", value="TypeScript"),
                                        dcc.Tab(label="TSX", value="TSX"),
                                        dcc.Tab(label="JavaScript", value="JavaScript"),
                                    ],
                                    parent_class_name="lang-tabs",
                                ),
                            ],
                            width=12,
                        )
                    ],
                    className="g-2",
                ),
                # Body: sidebar and main content
                dbc.Row(
                    [
                        # Sidebar
                        dbc.Col(
                            width=3,
                            children=[
                                # DB loader
                                dbc.Card(
                                    [
                                        dbc.CardHeader("Database"),
                                        dbc.CardBody(
                                            [
                                                dbc.Input(
                                                    id="db-path",
                                                    placeholder="Path to auditor.sqlite3",
                                                    value=DEFAULT_DB,
                                                ),
                                                dbc.Button(
                                                    "Load",
                                                    id="btn-load",
                                                    className="mt-2",
                                                    color="primary",
                                                    size="sm",
                                                ),
                                                html.Div(
                                                    id="db-status",
                                                    className="small text-muted mt-2",
                                                ),
                                            ]
                                        ),
                                    ],
                                    className="mb-3",
                                ),
                                # Folder tree
                                dbc.Card(
                                    [
                                        dbc.CardHeader("Folders"),
                                        dbc.CardBody(
                                            [
                                                dbc.Input(
                                                    id="folder-search",
                                                    placeholder="Search folders…",
                                                    debounce=True,
                                                    className="mb-2",
                                                ),
                                                dmc.Tree(
                                                    id="folder-tree",
                                                    data=[
                                                        {
                                                            "label": "All",
                                                            "value": "__ALL__",
                                                        }
                                                    ],
                                                    selected=["__ALL__"],
                                                    expanded=[],
                                                    selectOnClick=True,
                                                    style={
                                                        "height": "56vh",
                                                        "overflow": "auto",
                                                        "border": "1px solid #eee",
                                                        "padding": "6px",
                                                        "borderRadius": "0.5rem",
                                                    },
                                                ),
                                                dbc.Button(
                                                    "Reset to All",
                                                    id="btn-reset-all",
                                                    size="sm",
                                                    className="mt-2",
                                                ),
                                            ]
                                        ),
                                    ],
                                    className="mb-3",
                                ),
                                # Filters
                                dbc.Card(
                                    [
                                        dbc.CardHeader("Filters"),
                                        dbc.CardBody(
                                            [
                                                dbc.Label("Search"),
                                                dbc.Input(
                                                    id="text-query",
                                                    placeholder="Message / rule / file / tool / category",
                                                    debounce=True,
                                                ),
                                            ]
                                        ),
                                    ]
                                ),
                            ],
                        ),
                        # Main content
                        dbc.Col(
                            width=9,
                            children=[
                                dbc.Tabs(
                                    id="main-tabs",
                                    active_tab="tab-summary",
                                    children=[
                                        # Summary tab
                                        dbc.Tab(
                                            label="Summary",
                                            tab_id="tab-summary",
                                            children=[
                                                html.Div(
                                                    id="summary-header",
                                                    className="mb-2",
                                                ),
                                                dbc.Row(
                                                    [
                                                        dbc.Col(
                                                            kpi_card(
                                                                "Total issues",
                                                                "kpi-total",
                                                            ),
                                                            md=3,
                                                        ),
                                                        dbc.Col(
                                                            kpi_card(
                                                                "Files", "kpi-files"
                                                            ),
                                                            md=3,
                                                        ),
                                                        dbc.Col(
                                                            kpi_card(
                                                                "Tools", "kpi-tools"
                                                            ),
                                                            md=3,
                                                        ),
                                                        dbc.Col(
                                                            kpi_card(
                                                                "Gitleaks critical",
                                                                "kpi-gitleaks",
                                                            ),
                                                            md=3,
                                                        ),
                                                    ],
                                                    className="gy-3",
                                                ),
                                                dbc.Row(
                                                    [
                                                        dbc.Col(
                                                            dbc.Card(
                                                                [
                                                                    dbc.CardHeader(
                                                                        "Issues by tool"
                                                                    ),
                                                                    dbc.CardBody(
                                                                        [
                                                                            dcc.Graph(
                                                                                id="fig-by-tool"
                                                                            )
                                                                        ]
                                                                    ),
                                                                ]
                                                            ),
                                                            md=6,
                                                        ),
                                                        dbc.Col(
                                                            dbc.Card(
                                                                [
                                                                    dbc.CardHeader(
                                                                        "Issues by category"
                                                                    ),
                                                                    dbc.CardBody(
                                                                        [
                                                                            dcc.Graph(
                                                                                id="fig-by-category"
                                                                            )
                                                                        ]
                                                                    ),
                                                                ]
                                                            ),
                                                            md=6,
                                                        ),
                                                    ],
                                                    className="gy-3",
                                                ),
                                                dbc.Row(
                                                    [
                                                        dbc.Col(
                                                            dbc.Card(
                                                                [
                                                                    dbc.CardHeader(
                                                                        "Top files (by issues)"
                                                                    ),
                                                                    dbc.CardBody(
                                                                        [
                                                                            dcc.Graph(
                                                                                id="fig-by-file"
                                                                            )
                                                                        ]
                                                                    ),
                                                                ]
                                                            ),
                                                            md=6,
                                                        ),
                                                        dbc.Col(
                                                            dbc.Card(
                                                                [
                                                                    dbc.CardHeader(
                                                                        "Top tags"
                                                                    ),
                                                                    dbc.CardBody(
                                                                        [
                                                                            dcc.Graph(
                                                                                id="fig-by-tags"
                                                                            )
                                                                        ]
                                                                    ),
                                                                ]
                                                            ),
                                                            md=6,
                                                        ),
                                                    ],
                                                    className="gy-3",
                                                ),
                                            ],
                                        ),
                                        # Issues tab
                                        dbc.Tab(
                                            label="Issues",
                                            tab_id="tab-issues",
                                            children=[
                                                dbc.Card(
                                                    [
                                                        dbc.CardHeader(
                                                            "All issues (filtered)"
                                                        ),
                                                        dbc.CardBody(
                                                            [
                                                                dag.AgGrid(
                                                                    id="issues-grid",
                                                                    columnDefs=[
                                                                        {
                                                                            "field": "tool",
                                                                            "filter": True,
                                                                            "minWidth": 110,
                                                                        },
                                                                        {
                                                                            "field": "kind",
                                                                            "filter": True,
                                                                            "minWidth": 110,
                                                                        },
                                                                        {
                                                                            "field": "category",
                                                                            "filter": True,
                                                                            "minWidth": 110,
                                                                        },
                                                                        {
                                                                            "field": "rule_id",
                                                                            "headerName": "rule",
                                                                            "filter": True,
                                                                            "minWidth": 120,
                                                                        },
                                                                        {
                                                                            "field": "name",
                                                                            "filter": True,
                                                                            "minWidth": 140,
                                                                        },
                                                                        {
                                                                            "field": "message",
                                                                            "filter": True,
                                                                            "wrapText": True,
                                                                            "autoHeight": True,
                                                                            "minWidth": 260,
                                                                            "flex": 2,
                                                                        },
                                                                        {
                                                                            "field": "rel_file",
                                                                            "headerName": "file",
                                                                            "filter": True,
                                                                            "minWidth": 220,
                                                                            "flex": 1,
                                                                        },
                                                                        {
                                                                            "field": "line",
                                                                            "type": "rightAligned",
                                                                            "maxWidth": 90,
                                                                        },
                                                                        {
                                                                            "field": "col",
                                                                            "type": "rightAligned",
                                                                            "maxWidth": 90,
                                                                        },
                                                                        {
                                                                            "field": "complexity",
                                                                            "headerName": "complexity",
                                                                            "type": "rightAligned",
                                                                            "minWidth": 110,
                                                                        },
                                                                        {
                                                                            "field": "started_at",
                                                                            "headerName": "scan started",
                                                                            "filter": True,
                                                                            "minWidth": 160,
                                                                        },
                                                                    ],
                                                                    defaultColDef={
                                                                        "sortable": True,
                                                                        "resizable": True,
                                                                        "filter": True,
                                                                    },
                                                                    dashGridOptions={
                                                                        "rowHeight": 40,
                                                                        "animateRows": False,
                                                                        "pagination": True,
                                                                        "paginationPageSize": 20,
                                                                    },
                                                                    className="ag-theme-alpine",
                                                                )
                                                            ]
                                                        ),
                                                    ]
                                                ),
                                            ],
                                        ),
                                        # Tool Details tab (retained from original but unchanged here)
                                        dbc.Tab(
                                            label="Tool Details",
                                            tab_id="tab-tool",
                                            children=[
                                                dbc.Card(
                                                    [
                                                        dbc.CardHeader("Pick a tool"),
                                                        dbc.CardBody(
                                                            [
                                                                dcc.Dropdown(
                                                                    id="tool-dd",
                                                                    options=[],
                                                                    value=None,
                                                                    placeholder="Select a tool",
                                                                ),
                                                                html.Div(
                                                                    id="tool-context",
                                                                    className="text-muted mt-2",
                                                                ),
                                                            ]
                                                        ),
                                                    ],
                                                    className="mb-3",
                                                ),
                                                # KPIs for selected tool
                                                dbc.Row(
                                                    [
                                                        dbc.Col(
                                                            kpi_card(
                                                                "Issues (tool)",
                                                                "kpi-tool-issues",
                                                            ),
                                                            md=3,
                                                        ),
                                                        dbc.Col(
                                                            kpi_card(
                                                                "Files",
                                                                "kpi-tool-files",
                                                            ),
                                                            md=3,
                                                        ),
                                                        dbc.Col(
                                                            kpi_card(
                                                                "Unique rules",
                                                                "kpi-tool-rules",
                                                            ),
                                                            md=3,
                                                        ),
                                                        dbc.Col(
                                                            kpi_card(
                                                                "Last seen",
                                                                "kpi-tool-last",
                                                            ),
                                                            md=3,
                                                        ),
                                                    ],
                                                    className="gy-3",
                                                ),
                                                dbc.Row(
                                                    [
                                                        dbc.Col(
                                                            dbc.Card(
                                                                [
                                                                    dbc.CardHeader(
                                                                        "Issues over time (daily)"
                                                                    ),
                                                                    dbc.CardBody(
                                                                        [
                                                                            dcc.Graph(
                                                                                id="fig-tool-time"
                                                                            )
                                                                        ]
                                                                    ),
                                                                ]
                                                            ),
                                                            md=12,
                                                        ),
                                                    ],
                                                    className="gy-3",
                                                ),
                                                dbc.Row(
                                                    [
                                                        dbc.Col(
                                                            dbc.Card(
                                                                [
                                                                    dbc.CardHeader(
                                                                        "Issues by category"
                                                                    ),
                                                                    dbc.CardBody(
                                                                        [
                                                                            dcc.Graph(
                                                                                id="fig-tool-category"
                                                                            )
                                                                        ]
                                                                    ),
                                                                ]
                                                            ),
                                                            md=6,
                                                        ),
                                                        dbc.Col(
                                                            dbc.Card(
                                                                [
                                                                    dbc.CardHeader(
                                                                        "Top rules"
                                                                    ),
                                                                    dbc.CardBody(
                                                                        [
                                                                            dcc.Graph(
                                                                                id="fig-tool-rules"
                                                                            )
                                                                        ]
                                                                    ),
                                                                ]
                                                            ),
                                                            md=6,
                                                        ),
                                                    ],
                                                    className="gy-3",
                                                ),
                                                # Raw table for selected tool
                                                dbc.Card(
                                                    [
                                                        dbc.CardHeader(
                                                            "Tool-specific findings (filtered)"
                                                        ),
                                                        dbc.CardBody(
                                                            [
                                                                dag.AgGrid(
                                                                    id="tool-issues-grid",
                                                                    columnDefs=[
                                                                        {
                                                                            "field": "rule_id",
                                                                            "headerName": "rule",
                                                                            "filter": True,
                                                                            "minWidth": 120,
                                                                        },
                                                                        {
                                                                            "field": "name",
                                                                            "filter": True,
                                                                            "minWidth": 140,
                                                                        },
                                                                        {
                                                                            "field": "kind",
                                                                            "filter": True,
                                                                            "minWidth": 110,
                                                                        },
                                                                        {
                                                                            "field": "category",
                                                                            "filter": True,
                                                                            "minWidth": 110,
                                                                        },
                                                                        {
                                                                            "field": "message",
                                                                            "filter": True,
                                                                            "wrapText": True,
                                                                            "autoHeight": True,
                                                                            "minWidth": 260,
                                                                            "flex": 2,
                                                                        },
                                                                        {
                                                                            "field": "rel_file",
                                                                            "headerName": "file",
                                                                            "filter": True,
                                                                            "minWidth": 240,
                                                                            "flex": 1,
                                                                        },
                                                                        {
                                                                            "field": "line",
                                                                            "type": "rightAligned",
                                                                            "maxWidth": 90,
                                                                        },
                                                                        {
                                                                            "field": "col",
                                                                            "type": "rightAligned",
                                                                            "maxWidth": 90,
                                                                        },
                                                                        {
                                                                            "field": "complexity",
                                                                            "type": "rightAligned",
                                                                            "headerName": "complexity",
                                                                            "minWidth": 110,
                                                                        },
                                                                        {
                                                                            "field": "started_at",
                                                                            "headerName": "scan started",
                                                                            "filter": True,
                                                                            "minWidth": 160,
                                                                        },
                                                                    ],
                                                                    defaultColDef={
                                                                        "sortable": True,
                                                                        "resizable": True,
                                                                        "filter": True,
                                                                    },
                                                                    dashGridOptions={
                                                                        "rowHeight": 40,
                                                                        "animateRows": False,
                                                                        "pagination": True,
                                                                        "paginationPageSize": 20,
                                                                    },
                                                                    className="ag-theme-alpine",
                                                                )
                                                            ]
                                                        ),
                                                    ],
                                                    className="mt-3",
                                                ),
                                            ],
                                        ),
                                        # Compare Folders tab (unchanged)
                                        dbc.Tab(
                                            label="Compare Folders",
                                            tab_id="tab-compare",
                                            children=[
                                                dbc.Card(
                                                    [
                                                        dbc.CardHeader(
                                                            "Pick two root-level folders to compare"
                                                        ),
                                                        dbc.CardBody(
                                                            [
                                                                dbc.Row(
                                                                    [
                                                                        dbc.Col(
                                                                            [
                                                                                dbc.Label(
                                                                                    "Folder A"
                                                                                ),
                                                                                dcc.Dropdown(
                                                                                    id="compare-folder-a",
                                                                                    options=[],
                                                                                    value=None,
                                                                                    placeholder="Select Folder A",
                                                                                ),
                                                                            ],
                                                                            md=6,
                                                                        ),
                                                                        dbc.Col(
                                                                            [
                                                                                dbc.Label(
                                                                                    "Folder B"
                                                                                ),
                                                                                dcc.Dropdown(
                                                                                    id="compare-folder-b",
                                                                                    options=[],
                                                                                    value=None,
                                                                                    placeholder="Select Folder B",
                                                                                ),
                                                                            ],
                                                                            md=6,
                                                                        ),
                                                                    ],
                                                                    className="g-2",
                                                                ),
                                                                html.Div(
                                                                    className="text-muted mt-2",
                                                                    children="Tip: These are top-level folders derived from the filtered language's files (rel_file).",
                                                                ),
                                                            ]
                                                        ),
                                                    ],
                                                    className="mb-3",
                                                ),
                                                dbc.Row(
                                                    [
                                                        dbc.Col(
                                                            dbc.Card(
                                                                [
                                                                    dbc.CardHeader(
                                                                        "Issues over time (per day)"
                                                                    ),
                                                                    dbc.CardBody(
                                                                        [
                                                                            dcc.Graph(
                                                                                id="fig-compare-time"
                                                                            )
                                                                        ]
                                                                    ),
                                                                ]
                                                            ),
                                                            md=12,
                                                        ),
                                                    ],
                                                    className="gy-3",
                                                ),
                                                dbc.Row(
                                                    [
                                                        dbc.Col(
                                                            dbc.Card(
                                                                [
                                                                    dbc.CardHeader(
                                                                        "Issues by tool (grouped)"
                                                                    ),
                                                                    dbc.CardBody(
                                                                        [
                                                                            dcc.Graph(
                                                                                id="fig-compare-tool"
                                                                            )
                                                                        ]
                                                                    ),
                                                                ]
                                                            ),
                                                            md=6,
                                                        ),
                                                        dbc.Col(
                                                            dbc.Card(
                                                                [
                                                                    dbc.CardHeader(
                                                                        "Issues by category (grouped)"
                                                                    ),
                                                                    dbc.CardBody(
                                                                        [
                                                                            dcc.Graph(
                                                                                id="fig-compare-category"
                                                                            )
                                                                        ]
                                                                    ),
                                                                ]
                                                            ),
                                                            md=6,
                                                        ),
                                                    ],
                                                    className="gy-3",
                                                ),
                                            ],
                                        ),
                                        # Complexity tab
                                        dbc.Tab(
                                            label="Complexity",
                                            tab_id="tab-complexity",
                                            children=[
                                                dbc.Card(
                                                    [
                                                        dbc.CardHeader(
                                                            "Complexity distribution"
                                                        ),
                                                        dbc.CardBody(
                                                            [
                                                                dcc.Graph(
                                                                    id="fig-complexity-dist"
                                                                )
                                                            ]
                                                        ),
                                                    ],
                                                    className="mb-3",
                                                ),
                                                dbc.Row(
                                                    [
                                                        dbc.Col(
                                                            dbc.Card(
                                                                [
                                                                    dbc.CardHeader(
                                                                        "Top complexity items"
                                                                    ),
                                                                    dbc.CardBody(
                                                                        [
                                                                            dcc.Graph(
                                                                                id="fig-complexity-top"
                                                                            )
                                                                        ]
                                                                    ),
                                                                ]
                                                            ),
                                                            md=6,
                                                        ),
                                                        dbc.Col(
                                                            dbc.Card(
                                                                [
                                                                    dbc.CardHeader(
                                                                        "Complexity table"
                                                                    ),
                                                                    dbc.CardBody(
                                                                        [
                                                                            dag.AgGrid(
                                                                                id="complexity-grid",
                                                                                columnDefs=[
                                                                                    {
                                                                                        "field": "tool",
                                                                                        "filter": True,
                                                                                        "minWidth": 110,
                                                                                    },
                                                                                    {
                                                                                        "field": "kind",
                                                                                        "filter": True,
                                                                                        "minWidth": 110,
                                                                                    },
                                                                                    {
                                                                                        "field": "category",
                                                                                        "filter": True,
                                                                                        "minWidth": 110,
                                                                                    },
                                                                                    {
                                                                                        "field": "rel_file",
                                                                                        "headerName": "file",
                                                                                        "filter": True,
                                                                                        "minWidth": 240,
                                                                                        "flex": 1,
                                                                                    },
                                                                                    {
                                                                                        "field": "complexity",
                                                                                        "type": "rightAligned",
                                                                                        "minWidth": 100,
                                                                                    },
                                                                                    {
                                                                                        "field": "message",
                                                                                        "filter": True,
                                                                                        "wrapText": True,
                                                                                        "autoHeight": True,
                                                                                        "minWidth": 280,
                                                                                        "flex": 2,
                                                                                    },
                                                                                    {
                                                                                        "field": "started_at",
                                                                                        "headerName": "scan started",
                                                                                        "filter": True,
                                                                                        "minWidth": 160,
                                                                                    },
                                                                                ],
                                                                                defaultColDef={
                                                                                    "sortable": True,
                                                                                    "resizable": True,
                                                                                    "filter": True,
                                                                                },
                                                                                dashGridOptions={
                                                                                    "rowHeight": 40,
                                                                                    "animateRows": False,
                                                                                    "pagination": True,
                                                                                    "paginationPageSize": 20,
                                                                                },
                                                                                className="ag-theme-alpine",
                                                                            )
                                                                        ]
                                                                    ),
                                                                ]
                                                            ),
                                                            md=6,
                                                        ),
                                                    ],
                                                    className="gy-3",
                                                ),
                                            ],
                                        ),
                                    ],
                                ),
                            ],
                        ),
                    ]
                ),
            ],
        )
    ],
)


# ---------- Callbacks ----------
# Load data from SQLite when user clicks the Load button
@app.callback(
    Output("store-raw", "data"),
    Output("db-status", "children"),
    Input("btn-load", "n_clicks"),
    State("db-path", "value"),
    prevent_initial_call=True,
)
def load_data(n_clicks, path):
    path = path or DEFAULT_DB
    df, status = load_df(path)
    return df.to_json(date_unit="s", orient="records"), status


# Build tree and folder tree state
@app.callback(
    Output("store-tree", "data"),
    Output("folder-tree", "data"),
    Output("folder-tree", "selected"),
    Input("store-raw", "data"),
    Input("folder-search", "value"),
    State("folder-tree", "selected"),
    prevent_initial_call=True,
)
def make_tree(raw_json, q, current_selected):
    if not raw_json or raw_json == "[]":
        return (
            [{"label": "All", "value": "__ALL__"}],
            [{"label": "All", "value": "__ALL__"}],
            ["__ALL__"],
        )
    df = pd.read_json(
        StringIO(raw_json),
        orient="records",
        convert_dates=["started_at", "finished_at"],
    )
    paths = sorted(df["rel_file"].dropna().unique().tolist())
    full_tree = build_tree_data(paths)

    def filter_nodes(nodes, term):
        out: List[Dict[str, Any]] = []
        term = (term or "").lower().strip()
        for n in nodes:
            label = str(n.get("label", ""))
            value = str(n.get("value", ""))
            kids = n.get("children", [])
            fk = filter_nodes(kids, term) if kids else []
            keep = (not term) or (term in label.lower()) or (term in value.lower())
            if keep or fk:
                m = dict(n)
                if fk:
                    m["children"] = fk
                out.append(m)
        return out

    view_tree = filter_nodes(full_tree, q)

    def _flatten_values(nodes):
        vals: List[str] = []
        for n in nodes:
            vals.append(n.get("value"))
            for c in n.get("children", []):
                vals.extend(_flatten_values([c]))
        return vals

    flat = _flatten_values(view_tree)
    new_selected = (
        current_selected
        if current_selected and all(v in flat for v in current_selected)
        else ["__ALL__"]
    )
    return full_tree, view_tree, new_selected


# Filter data based on language, folder and search query
@app.callback(
    Output("store-filtered", "data"),
    Input("store-raw", "data"),
    Input("lang-tabs", "value"),
    Input("text-query", "value"),
    Input("btn-reset-all", "n_clicks"),
    Input("folder-tree", "selected"),
    prevent_initial_call=True,
)
def compute_filtered(raw_json, lang, text_query, _reset_clicks, selected):
    if not raw_json:
        return no_update
    df = pd.read_json(
        StringIO(raw_json),
        orient="records",
        convert_dates=["started_at", "finished_at"],
    )
    folder_value = (
        "__ALL__"
        if ctx.triggered_id == "btn-reset-all"
        else ((selected or ["__ALL__"])[0])
    )
    dff = filter_df(
        df, language=lang, folder_value=folder_value, text_query=text_query or ""
    )
    return dff.to_json(date_unit="s", orient="records")


# Populate folder drop-downs for Compare page
@app.callback(
    Output("compare-folder-a", "options"),
    Output("compare-folder-b", "options"),
    Output("compare-folder-a", "value"),
    Output("compare-folder-b", "value"),
    Input("store-raw", "data"),
    Input("lang-tabs", "value"),
    prevent_initial_call=True,
)
def compare_options(raw_json, lang):
    if not raw_json:
        return [], [], None, None
    df = pd.read_json(
        StringIO(raw_json),
        orient="records",
        convert_dates=["started_at", "finished_at"],
    )
    for col in ["rel_file", "top_level"]:
        if col not in df.columns:
            df[col] = pd.Series(dtype="object")
    exts = LANG_EXT.get(lang, [])
    df_lang = df[df["rel_file"].apply(lambda p: _file_ext_match(p, exts))].copy()
    tops = df_lang["top_level"].dropna().astype(str).unique().tolist()
    # Put non-root first then root
    tops = sorted(tops, key=lambda s: (s == "(root)", s.lower()))
    opts = [{"label": t, "value": t} for t in tops]
    default_a = tops[0] if tops else None
    default_b = tops[1] if len(tops) > 1 else (tops[0] if tops else None)
    return opts, opts, default_a, default_b


# Update summary KPIs and charts
@app.callback(
    Output("summary-header", "children"),
    Output("kpi-total", "children"),
    Output("kpi-files", "children"),
    Output("kpi-tools", "children"),
    Output("kpi-gitleaks", "children"),
    Output("fig-by-tool", "figure"),
    Output("fig-by-category", "figure"),
    Output("fig-by-file", "figure"),
    Output("fig-by-tags", "figure"),
    Input("store-filtered", "data"),
    Input("lang-tabs", "value"),
    State("folder-tree", "selected"),
    prevent_initial_call=True,
)
def update_summary(filtered_json, lang, selected):
    if not filtered_json:
        # Return empty state
        empty_fig = go.Figure()
        return (
            html.H5("No data loaded", className="mb-3"),
            "0",
            "0",
            "0",
            "0",
            empty_fig,
            empty_fig,
            empty_fig,
            empty_fig,
        )

    df = pd.read_json(
        StringIO(filtered_json),
        orient="records",
        convert_dates=["started_at", "finished_at"],
    )
    for col in ["rel_file", "tool", "kind", "category", "tags_parsed", "started_at"]:
        if col not in df.columns:
            df[col] = pd.Series(dtype="object")

    folder_value = (
        (selected or ["__ALL__"])[0] if isinstance(selected, list) else "__ALL__"
    )
    where = "All folders" if folder_value == "__ALL__" else f"Folder: {folder_value}"
    header = html.H5(f"Summary · Language: {lang} · {where}", className="mb-3")

    # KPIs
    total_issues = len(df)
    total_files = df["rel_file"].nunique()
    total_tools = df["tool"].nunique()
    # Count critical gitleaks findings (tool == gitleaks and severity contains CRITICAL)
    df["severity"] = (
        df.get("severity", pd.Series([], dtype="object"))
        .fillna("UNKNOWN")
        .astype(str)
        .str.upper()
    )
    gitleaks_crit = len(
        df[(df["tool"].str.lower() == "gitleaks") & (df["severity"] == "CRITICAL")]
    )

    # Issues by tool (bar)
    if total_issues:
        by_tool = (
            df.groupby("tool", dropna=False)
            .size()
            .reset_index(name="count")
            .sort_values("count", ascending=False)
        )
        fig_tool = px.bar(by_tool, x="tool", y="count", title=None)
        fig_tool.update_layout(margin=dict(t=10, r=10, l=10, b=10))
    else:
        fig_tool = go.Figure()

    # Issues by category (bar)
    if total_issues:
        # Replace missing category with "Uncategorised"
        df["category"] = df["category"].fillna("Uncategorised").astype(str)
        by_cat = (
            df.groupby("category", dropna=False)
            .size()
            .reset_index(name="count")
            .sort_values("count", ascending=False)
        )
        fig_cat = px.bar(by_cat, x="category", y="count", title=None)
        fig_cat.update_layout(margin=dict(t=10, r=10, l=10, b=10), xaxis_tickangle=-45)
    else:
        fig_cat = go.Figure()

    # Top files by issues (bar, top 20)
    if total_issues:
        by_file = (
            df.groupby("rel_file", dropna=False)
            .size()
            .reset_index(name="count")
            .sort_values("count", ascending=False)
            .head(20)
        )
        fig_file = px.bar(by_file, x="rel_file", y="count", title=None)
        fig_file.update_layout(margin=dict(t=10, r=10, l=10, b=10), xaxis_tickangle=-45)
    else:
        fig_file = go.Figure()

    # Top tags (bar, flatten tags)
    if total_issues:
        # Flatten list of tags
        tags_series = pd.Series(
            [
                tag
                for sublist in df.get("tags_parsed", []).tolist()
                for tag in (sublist or [])
            ]
        )
        if not tags_series.empty:
            by_tag = (
                tags_series.value_counts()
                .reset_index()
                .rename(columns={"index": "tag", 0: "count"})
            )
            by_tag = by_tag.head(30)
            fig_tags = px.bar(by_tag, x="tag", y="count", title=None)
            fig_tags.update_layout(
                margin=dict(t=10, r=10, l=10, b=10), xaxis_tickangle=-45
            )
        else:
            fig_tags = go.Figure()
    else:
        fig_tags = go.Figure()

    return (
        header,
        f"{total_issues:,}",
        f"{total_files:,}",
        f"{total_tools:,}",
        f"{gitleaks_crit:,}",
        fig_tool,
        fig_cat,
        fig_file,
        fig_tags,
    )


# Populate Issues table
@app.callback(
    Output("issues-grid", "rowData"),
    Input("store-filtered", "data"),
    prevent_initial_call=True,
)
def fill_grid(filtered_json):
    df = pd.read_json(
        StringIO(filtered_json),
        orient="records",
        convert_dates=["started_at", "finished_at"],
    )
    if df.empty:
        return []
    df = df.fillna("")
    if "started_at" in df.columns:
        try:
            df["started_at"] = pd.to_datetime(df["started_at"]).dt.strftime(
                "%Y-%m-%d %H:%M"
            )
        except Exception:
            pass
    cols = [
        "tool",
        "kind",
        "category",
        "rule_id",
        "name",
        "message",
        "rel_file",
        "line",
        "col",
        "complexity",
        "started_at",
    ]
    for c in cols:
        if c not in df.columns:
            df[c] = ""
    return df[cols].to_dict("records")


# Compare Folders charts
@app.callback(
    Output("fig-compare-time", "figure"),
    Output("fig-compare-tool", "figure"),
    Output("fig-compare-category", "figure"),
    Input("store-raw", "data"),
    Input("lang-tabs", "value"),
    Input("compare-folder-a", "value"),
    Input("compare-folder-b", "value"),
    prevent_initial_call=True,
)
def compare_figs(raw_json, lang, folder_a, folder_b):
    # Helper to ensure columns exist
    def ensure_cols(dff: pd.DataFrame) -> pd.DataFrame:
        for c in ["rel_file", "tool", "category", "started_at", "top_level"]:
            if c not in dff.columns:
                dff[c] = pd.Series(dtype="object")
        return dff

    def subset_by_top(dff: pd.DataFrame, top: str) -> pd.DataFrame:
        if not top:
            return dff.iloc[0:0].copy()
        if top == "(root)":
            mask = ~dff["rel_file"].str.contains("/", na=False)
        else:
            mask = dff["rel_file"].str.startswith(top + "/", na=False)
        out = dff[mask].copy()
        out["__folder__"] = top
        return out

    # No raw data
    if not raw_json:
        empty_fig = go.Figure()
        return empty_fig, empty_fig, empty_fig

    df = pd.read_json(
        StringIO(raw_json),
        orient="records",
        convert_dates=["started_at", "finished_at"],
    )
    df = ensure_cols(df)
    # language filter
    exts = LANG_EXT.get(lang, [])
    dlang = df[df["rel_file"].apply(lambda p: _file_ext_match(p, exts))].copy()
    dlang = ensure_cols(dlang)
    # subsets
    A = subset_by_top(dlang, folder_a)
    B = subset_by_top(dlang, folder_b)
    comb = pd.concat([A, B], ignore_index=True)
    if comb.empty:
        empty_fig = go.Figure()
        return empty_fig, empty_fig, empty_fig

    # Issues over time
    if "started_at" in comb.columns:
        comb["date"] = pd.to_datetime(comb["started_at"], errors="coerce").dt.floor("D")
        by_day = (
            comb.dropna(subset=["date"])
            .groupby(["__folder__", "date"])
            .size()
            .reset_index(name="count")
            .sort_values(["__folder__", "date"])
        )
        fig_time = go.Figure()
        for folder, grp in by_day.groupby("__folder__"):
            fig_time.add_trace(
                go.Scatter(
                    x=grp["date"],
                    y=grp["count"],
                    mode="lines+markers",
                    name=str(folder),
                )
            )
        fig_time.update_layout(margin=dict(t=10, r=10, l=10, b=10))
    else:
        fig_time = go.Figure()

    # Grouped bar: by tool
    by_tool = (
        comb.groupby(["__folder__", "tool"], dropna=False)
        .size()
        .reset_index(name="count")
    )
    fig_tool = px.bar(
        by_tool, x="tool", y="count", color="__folder__", barmode="group", title=None
    )
    fig_tool.update_layout(
        margin=dict(t=10, r=10, l=10, b=10), xaxis={"categoryorder": "total descending"}
    )

    # Grouped bar: by category
    comb["category"] = comb["category"].fillna("Uncategorised").astype(str)
    by_cat = (
        comb.groupby(["__folder__", "category"], dropna=False)
        .size()
        .reset_index(name="count")
    )
    by_cat["category"] = by_cat["category"].astype(str)
    by_cat["category"] = pd.Categorical(
        by_cat["category"], categories=by_cat["category"].unique(), ordered=False
    )
    fig_cat = px.bar(
        by_cat, x="category", y="count", color="__folder__", barmode="group", title=None
    )
    fig_cat.update_layout(margin=dict(t=10, r=10, l=10, b=10), xaxis_tickangle=-45)
    return fig_time, fig_tool, fig_cat


# Complexity metrics callback
@app.callback(
    Output("fig-complexity-dist", "figure"),
    Output("fig-complexity-top", "figure"),
    Output("complexity-grid", "rowData"),
    Input("store-filtered", "data"),
    prevent_initial_call=True,
)
def update_complexity(filtered_json):
    if not filtered_json:
        empty_fig = go.Figure()
        return empty_fig, empty_fig, []
    df = pd.read_json(
        StringIO(filtered_json),
        orient="records",
        convert_dates=["started_at", "finished_at"],
    )
    # Only rows with a numeric complexity
    comp_df = df[
        pd.to_numeric(
            df.get("complexity", pd.Series(dtype="float")), errors="coerce"
        ).notna()
    ].copy()
    if comp_df.empty:
        empty_fig = go.Figure()
        return empty_fig, empty_fig, []
    comp_df["complexity"] = comp_df["complexity"].astype(float)
    # Distribution (histogram)
    fig_dist = px.histogram(comp_df, x="complexity", nbins=30, title=None)
    fig_dist.update_layout(
        margin=dict(t=10, r=10, l=10, b=10),
        xaxis_title="Cyclomatic complexity",
        yaxis_title="Count",
    )
    # Top complexity values (bar)
    top_comp = comp_df.sort_values("complexity", ascending=False).head(20)
    fig_top = px.bar(top_comp, x="rel_file", y="complexity", title=None)
    fig_top.update_layout(
        margin=dict(t=10, r=10, l=10, b=10),
        xaxis_tickangle=-45,
        xaxis_title="File",
        yaxis_title="Cyclomatic complexity",
    )
    # Data table
    comp_df_disp = comp_df.copy()
    if "started_at" in comp_df_disp.columns:
        comp_df_disp["started_at"] = pd.to_datetime(
            comp_df_disp["started_at"], errors="coerce"
        ).dt.strftime("%Y-%m-%d %H:%M")
    cols = [
        "tool",
        "kind",
        "category",
        "rel_file",
        "complexity",
        "message",
        "started_at",
    ]
    for c in cols:
        if c not in comp_df_disp.columns:
            comp_df_disp[c] = ""
    return fig_dist, fig_top, comp_df_disp[cols].fillna("").to_dict("records")


# Populate tool dropdown based on filtered data
@app.callback(
    Output("tool-dd", "options"),
    Output("tool-dd", "value"),
    Output("tool-context", "children"),
    Input("store-filtered", "data"),
    prevent_initial_call=True,
)
def tool_options(filtered_json):
    if not filtered_json:
        return [], None, "No data loaded."
    df = pd.read_json(
        StringIO(filtered_json),
        orient="records",
        convert_dates=["started_at", "finished_at"],
    )
    if df.empty or "tool" not in df.columns:
        return [], None, "No tools found in current filter."
    by_tool = (
        df.groupby("tool", dropna=False)
        .size()
        .reset_index(name="count")
        .sort_values("count", ascending=False)
    )
    options = [
        {"label": f"{t} ({c})", "value": t}
        for t, c in zip(by_tool["tool"], by_tool["count"])
    ]
    default = by_tool["tool"].iloc[0] if not by_tool.empty else None
    return options, default, f"Tools available in current filter: {len(by_tool)}"


# Render Tool Details KPIs, charts and grid
@app.callback(
    Output("kpi-tool-issues", "children"),
    Output("kpi-tool-files", "children"),
    Output("kpi-tool-rules", "children"),
    Output("kpi-tool-last", "children"),
    Output("fig-tool-time", "figure"),
    Output("fig-tool-category", "figure"),
    Output("fig-tool-rules", "figure"),
    Output("tool-issues-grid", "rowData"),
    Input("store-filtered", "data"),
    Input("tool-dd", "value"),
    prevent_initial_call=True,
)
def tool_detail(filtered_json, tool_value):
    if not filtered_json or not tool_value:
        empty_fig = go.Figure()
        return "0", "0", "0", "—", empty_fig, empty_fig, empty_fig, []
    df = pd.read_json(
        StringIO(filtered_json),
        orient="records",
        convert_dates=["started_at", "finished_at"],
    )
    for col in [
        "rel_file",
        "tool",
        "rule_id",
        "severity",
        "category",
        "kind",
        "message",
        "started_at",
    ]:
        if col not in df.columns:
            df[col] = pd.Series(dtype="object")
    dtool = df[df["tool"] == tool_value].copy()
    if dtool.empty:
        empty_fig = go.Figure()
        return "0", "0", "0", "—", empty_fig, empty_fig, empty_fig, []
    # KPIs
    issues_cnt = len(dtool)
    files_cnt = dtool["rel_file"].nunique()
    rules_cnt = (
        dtool["rule_id"]
        .astype(str)
        .replace({"nan": ""})
        .replace("", "(none)")
        .nunique()
    )
    last_seen = pd.to_datetime(dtool["started_at"], errors="coerce").max()
    last_seen_str = last_seen.strftime("%Y-%m-%d %H:%M") if pd.notna(last_seen) else "—"
    # Time series
    dtool["date"] = pd.to_datetime(dtool["started_at"], errors="coerce").dt.floor("D")
    by_day = (
        dtool.dropna(subset=["date"])
        .groupby("date")
        .size()
        .reset_index(name="count")
        .sort_values("date")
    )
    fig_time = go.Figure(
        go.Scatter(
            x=by_day["date"], y=by_day["count"], mode="lines+markers", name=tool_value
        )
    )
    fig_time.update_layout(margin=dict(t=10, r=10, l=10, b=10))
    # Category distribution for this tool
    dtool["category"] = dtool["category"].fillna("Uncategorised").astype(str)
    by_cat = (
        dtool.groupby("category", dropna=False)
        .size()
        .reset_index(name="count")
        .sort_values("count", ascending=False)
    )
    fig_cat = px.bar(by_cat, x="category", y="count", title=None)
    fig_cat.update_layout(margin=dict(t=10, r=10, l=10, b=10), xaxis_tickangle=-45)
    # Top rules
    dtool["rule_id"] = (
        dtool["rule_id"].astype(str).replace({"nan": ""}).replace("", "(none)")
    )
    by_rule = (
        dtool.groupby("rule_id", dropna=False)
        .size()
        .reset_index(name="count")
        .sort_values("count", ascending=False)
        .head(30)
    )
    fig_rules = px.bar(by_rule, x="rule_id", y="count", title=None)
    fig_rules.update_layout(
        margin=dict(t=10, r=10, l=10, b=10), xaxis={"categoryorder": "total descending"}
    )
    # Data table
    dtool_disp = dtool.copy()
    if "started_at" in dtool_disp.columns:
        dtool_disp["started_at"] = pd.to_datetime(
            dtool_disp["started_at"], errors="coerce"
        ).dt.strftime("%Y-%m-%d %H:%M")
    cols = [
        "rule_id",
        "name",
        "kind",
        "category",
        "message",
        "rel_file",
        "line",
        "col",
        "complexity",
        "started_at",
    ]
    for c in cols:
        if c not in dtool_disp.columns:
            dtool_disp[c] = ""
    rows = dtool_disp[cols].fillna("").to_dict("records")
    return (
        f"{issues_cnt:,}",
        f"{files_cnt:,}",
        f"{rules_cnt:,}",
        last_seen_str,
        fig_time,
        fig_cat,
        fig_rules,
        rows,
    )


# Add simple CSS via index string
app.index_string = """
<!DOCTYPE html>
<html>
    <head>
        {%metas%}
        <title>{%title%}</title>
        {%favicon%}
        {%css%}
        <style>
          .kpi-card { min-height: 110px; }
          .kpi-title { font-size: 0.85rem; color: #6c757d; text-transform: uppercase; letter-spacing: .04em; }
          .kpi-value { font-weight: 700; margin: 0; }
          .lang-tabs { margin-top: 0.5rem; }
          .ag-theme-alpine { --ag-odd-row-background-color: #fafafa; --ag-header-background-color: #f5f5f5; }
        </style>
    </head>
    <body>
        {%app_entry%}
        <footer>
            {%config%}
            {%scripts%}
            {%renderer%}
        </footer>
    </body>
</html>
"""


# Main entry point
if __name__ == "__main__":
    app.run_server(host="0.0.0.0", port=int(os.environ.get("PORT", 8050)), debug=True)
