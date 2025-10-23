from __future__ import annotations

from contextlib import contextmanager
from typing import Iterable, Tuple

from sqlalchemy import inspect
from sqlalchemy.orm import Session, sessionmaker

from .connection import get_engine


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


def save_scan_and_rows(
    Base, scan_row, result_rows, upsert: bool = False
) -> Tuple[int, int]:  # noqa: ARG001
    with get_session() as session:
        _attach(session, scan_row)
        for row in result_rows:
            _attach(session, row)
        session.flush()
        return 1, len(result_rows)


__all__ = ["get_session", "init_db", "save_scan_and_rows"]
