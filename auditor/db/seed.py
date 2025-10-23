from __future__ import annotations

from typing import Callable

from sqlalchemy import text

from .connection import get_engine, get_db_path
from .utils import init_db


def seed_database(Base) -> None:  # noqa: N803
    engine = get_engine()
    with engine.connect() as conn:
        conn.execute(text("PRAGMA journal_mode=WAL"))
        conn.execute(text("PRAGMA synchronous = NORMAL"))
        conn.commit()
    init_db(Base)


def describe_database() -> str:
    return str(get_db_path())


__all__ = ["seed_database", "describe_database"]
