from __future__ import annotations

"""Core data models for static analysis results.

This package contains ORM models and schema definitions for storing and
retrieving static analysis results from the database.

Modules
-------
orm : SQLAlchemy ORM models
schema : Pydantic schema models
parsers : Tool output parsers

See Also
--------
auditor.infra.db : Database utilities
"""

from .schema import *
