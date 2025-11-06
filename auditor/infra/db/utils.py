"""Database utility functions.

This module provides helper functions for common database operations including
session management and query helpers.

Functions
---------
get_session : Get database session context manager
save_scan_and_rows : Save scan and associated rows

Examples
--------
>>> with get_session() as sess:
...     count = sess.query(Model).count()

See Also
--------
auditor.infra.db.connection : Connection management
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterable, Tuple

from sqlalchemy import inspect
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy import insert
from ...core.models.orm import ScanMetadata
from ...core.models.parsers._shared import now_iso

from typing import DefaultDict, List

from .connection import get_engine

from collections import defaultdict
from typing import Sequence, Dict, Any, Type
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.dialects.postgresql import insert as pg_insert

from auditor.core.models.orm import Base
SessionLocal = sessionmaker(
    bind=get_engine(), autoflush=False, autocommit=False, future=True
)


@contextmanager
def get_session() -> Iterable[Session]:
    session: Session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db(Base) -> None:  # noqa: N803 - SQLAlchemy convention
    Base.metadata.create_all(bind=get_engine())


def _attach(session: Session, obj) -> None:
    if obj is None:
        return
    if inspect(obj).session is session:
        return
    if inspect(obj).session is None:
        session.add(obj)


def _as_row_dicts(cls: Type[Base], rows: Sequence[Base]) -> list[dict[str, Any]]:
    cols = [c.name for c in cls.__table__.columns]  # includes 'pk'
    out = []
    for r in rows:
        out.append({c: getattr(r, c) for c in cols})
    return out


def save_scan_and_rows(
    Base, scan_row, result_rows, upsert: bool = False
) -> Tuple[int, int]:
    
    if scan_row is None:
        scan_row = ScanMetadata(scan_timestamp=now_iso())
    
    with get_session() as session:
        # 1) persist scan to get id
        session.add(scan_row)
        session.flush()  # ensures scan_row.id is populated
        scan_id = scan_row.id

        # 2) attach scan & compute pk; dedupe in-memory
        by_cls: DefaultDict[type, List[object]] = defaultdict(list)
        seen_pks: set[str] = set()
        result_rows = [r for r in (result_rows or []) if r is not None]

        for row in result_rows or []:
            # make sure the FK/relationship is set
            if getattr(row, "scan", None) is None and getattr(row, "scan_id", None) is None:
                row.scan_id = scan_id
            else:
                row.scan = scan_row

            # ensure PK is present before we try to dedupe
            if not getattr(row, "pk", None):
                row.pk = row.build_pk()

            if row.pk in seen_pks:
                continue
            seen_pks.add(row.pk)
            by_cls[type(row)].append(row)

        # 3) bulk insert with "do nothing on conflict" where possible
        inserted = 0
        dialect = session.bind.dialect.name

        for cls, rows in by_cls.items():
            if not rows:
                continue

            if upsert and dialect in ("sqlite", "postgresql"):
                payloads = [{col.name: getattr(r, col.name) for col in cls.__table__.columns} for r in rows]

                if dialect == "sqlite":
                    stmt = insert(cls).values(payloads).on_conflict_do_nothing(index_elements=["pk"])
                else:
                    from sqlalchemy.dialects.postgresql import insert as pg_insert
                    stmt = pg_insert(cls).values(payloads).on_conflict_do_nothing(index_elements=["pk"])

                session.execute(stmt)
                inserted += len(rows)  # rows attempted; conflicts are ignored
            else:
                # fallback: ORM add_all with per-row conflict guard
                try:
                    session.add_all(rows)
                    session.flush()
                    inserted += len(rows)
                except IntegrityError:
                    session.rollback()
                    for r in rows:
                        try:
                            session.add(r)
                            session.flush()
                            inserted += 1
                        except IntegrityError:
                            session.rollback()  # ignore duplicates

        session.commit()
        return scan_id, inserted

__all__ = ["get_session", "init_db", "save_scan_and_rows"]
