"""Database schema initialization and seeding.

This module provides functions to create database tables and optionally
populate them with seed data.

Functions
---------
seed_database : Initialize database schema

Examples
--------
>>> from auditor.core.models.orm import Base
>>> seed_database(Base)

See Also
--------
auditor.core.models.orm : ORM models
"""
from __future__ import annotations


from sqlalchemy import text

from .connection import get_engine
from .utils import init_db


def seed_database(Base) -> None:  # noqa: N803
    engine = get_engine()
    with engine.connect() as conn:
        conn.execute(text("PRAGMA journal_mode=WAL"))
        conn.execute(text("PRAGMA synchronous = NORMAL"))
        conn.commit()
    init_db(Base)


__all__ = ["seed_database"]
