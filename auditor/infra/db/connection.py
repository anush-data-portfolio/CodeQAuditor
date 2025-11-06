"""Database connection management.

This module handles database connection pooling, session management,
and connection lifecycle.

Functions
---------
get_engine : Get SQLAlchemy engine
get_session : Get database session context manager

Examples
--------
>>> with get_session() as session:
...     session.query(Model).all()

See Also
--------
auditor.infra.db.utils : Database utilities
"""
from __future__ import annotations

from functools import lru_cache

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine

from config import CONFIG


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    engine = create_engine(
        f"{CONFIG.database_url}",
        connect_args={"check_same_thread": False},
        echo=False,
        future=True,
    )
    return engine


__all__ = ["get_engine"]
