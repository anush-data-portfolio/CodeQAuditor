from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Optional

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine


def _resolve_db_path() -> Path:
    override = os.getenv("AUDITORDBPATH")
    path = Path(override) if override else Path("out") / "auditor.sqlite3"
    if not path.is_absolute():
        path = Path.cwd() / path
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    db_path = _resolve_db_path()
    echo_flag = os.getenv("AUDITORDBECHO", "0")
    echo = echo_flag not in {"", "0", "false", "False"}
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
        echo=echo,
        future=True,
    )
    return engine


def get_db_path() -> Path:
    return Path(str(_resolve_db_path()))


__all__ = ["get_engine", "get_db_path"]
