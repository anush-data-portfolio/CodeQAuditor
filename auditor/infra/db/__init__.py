from __future__ import annotations

"""Database infrastructure and utilities.

This package contains database connection management, bulk operations,
query optimization, and initialization utilities.

Modules
-------
connection : Database connection management
bulk_operations : Bulk insert/update operations
optimized_queries : Performance-optimized queries
seed : Database schema initialization
utils : General database utilities

Examples
--------
>>> from auditor.infra.db import get_session
>>> with get_session() as session:
...     results = session.query(BanditResult).all()

See Also
--------
auditor.core.models.orm : ORM models
"""

from .connection import get_engine

__all__ = ["get_engine"]
