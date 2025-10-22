# auditor/storage/writers.py
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tool TEXT NOT NULL,
  repo_path TEXT NOT NULL,
  started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  finished_at DATETIME,
  returncode INTEGER,
  duration_s REAL,
  stdout_bytes INTEGER,
  stderr_bytes INTEGER
);

CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  tool TEXT NOT NULL,
  name TEXT,
  rule_id TEXT,
  message TEXT,
  file TEXT,
  line INTEGER,
  col INTEGER,
  end_line INTEGER,
  end_col INTEGER,
  fingerprint TEXT,
  extra_json TEXT,
  kind TEXT,
  category TEXT,
  metrics_json TEXT,
  tags TEXT
);
"""


class SQLiteWriter:
    def __init__(self, db_path: str = "auditor.sqlite3") -> None:
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._conn.executescript(SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def start_scan(self, tool: str, repo_path: str) -> int:
        cur = self._conn.cursor()
        cur.execute(
            "INSERT INTO scans(tool, repo_path) VALUES (?, ?)",
            (tool, str(Path(repo_path).resolve())),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def finish_scan(self, scan_id: int, *, returncode: int, duration_s: float, stdout_bytes: int, stderr_bytes: int):
        self._conn.execute(
            "UPDATE scans SET finished_at=CURRENT_TIMESTAMP, returncode=?, duration_s=?, stdout_bytes=?, stderr_bytes=? WHERE id=?",
            (returncode, duration_s, stdout_bytes, stderr_bytes, scan_id),
        )
        self._conn.commit()

    def write_findings(self, scan_id: int, findings: Iterable[Dict[str, Any]]) -> int:
        rows = []
        for f in findings:
            rows.append(
                (
                    scan_id,
                    f.get("tool"),
                    f.get("name"),
                    f.get("rule_id"),
                    f.get("message"),
                    f.get("file"),
                    f.get("line"),
                    f.get("col"),
                    f.get("end_line"),
                    f.get("end_col"),
                    f.get("fingerprint"),
                    json_dumps_safe(f.get("extra")),
                    f.get("kind"),
                    f.get("category"),
                    json_dumps_safe(f.get("metrics")),
                    ",".join(f.get("tags") or []),

                )
            )
        cur = self._conn.cursor()
        cur.executemany(
            """INSERT INTO findings(
                   scan_id, tool, name, rule_id, message, file,
                   line, col, end_line, end_col, fingerprint, extra_json,
                   kind, category, metrics_json, tags
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,  ?)""",
            rows,
        )
        self._conn.commit()
        return cur.rowcount


def json_dumps_safe(obj: Any) -> Optional[str]:
    import json

    if obj is None:
        return None
    try:
        return json.dumps(obj, ensure_ascii=False)
    except Exception:
        return None
