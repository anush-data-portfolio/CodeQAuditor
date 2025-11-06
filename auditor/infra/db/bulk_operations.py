# Copyright (c) 2025 Anush Krishna
# Licensed under the MIT License. See LICENSE file in the project root.

from __future__ import annotations

"""Bulk database operations for performance optimization.

This module provides functions for efficient bulk insert and update operations
to improve performance when storing large numbers of analysis results.

Functions
---------
bulk_insert : Insert multiple records efficiently
bulk_update : Update multiple records efficiently

Examples
--------
>>> from auditor.infra.db.bulk_operations import bulk_insert
>>> bulk_insert(session, BanditResult, records)

See Also
--------
auditor.infra.db.utils : Database utilities
"""

"""
Bulk database operations for improved performance.

This module provides optimized bulk insert, update, and delete operations
to reduce database round-trips and improve overall performance.
"""

from typing import List, Type, TypeVar, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from auditor.core.logging_config import get_logger
from auditor.core.exceptions import DatabaseError

logger = get_logger(__name__)

T = TypeVar('T')


def bulk_insert_or_update(
    session: Session,
    model_class: Type[T],
    records: List[Dict[str, Any]],
    batch_size: int = 1000
) -> int:
    """
    Perform bulk insert or update operations.
    
    Uses SQLite's INSERT OR REPLACE for efficient upserts.
    Processes records in batches to manage memory usage.
    
    Args:
        session: SQLAlchemy session
        model_class: ORM model class
        records: List of dictionaries with record data
        batch_size: Number of records to process per batch
        
    Returns:
        Total number of records processed
        
    Raises:
        DatabaseError: If bulk operation fails
        
    Example:
        >>> records = [{'pk': '123', 'file_path': 'test.py', ...}]
        >>> count = bulk_insert_or_update(session, BanditResult, records)
    """
    if not records:
        return 0
    
    total_processed = 0
    
    try:
        for i in range(0, len(records), batch_size):
            batch = records[i:i + batch_size]
            
            # For SQLite, use INSERT OR REPLACE
            stmt = sqlite_insert(model_class).values(batch)
            stmt = stmt.on_conflict_do_update(
                index_elements=['pk'],
                set_={k: stmt.excluded[k] for k in batch[0].keys() if k != 'pk'}
            )
            
            session.execute(stmt)
            total_processed += len(batch)
            
            if (i + batch_size) % 10000 == 0:
                logger.debug(f"Processed {total_processed} records...")
        
        session.commit()
        logger.info(f"Bulk inserted/updated {total_processed} {model_class.__tablename__} records")
        
        return total_processed
        
    except Exception as e:
        session.rollback()
        logger.error(f"Bulk operation failed: {e}")
        raise DatabaseError(
            "bulk_insert",
            f"Failed to bulk insert {model_class.__tablename__} records",
            {"error": str(e), "record_count": len(records)}
        )


def bulk_insert_models(
    session: Session,
    models: List[T],
    batch_size: int = 1000
) -> int:
    """
    Bulk insert ORM model instances.
    
    More efficient than adding models individually.
    
    Args:
        session: SQLAlchemy session
        models: List of ORM model instances
        batch_size: Number of models to insert per batch
        
    Returns:
        Number of models inserted
        
    Raises:
        DatabaseError: If bulk insert fails
    """
    if not models:
        return 0
    
    total_inserted = 0
    
    try:
        for i in range(0, len(models), batch_size):
            batch = models[i:i + batch_size]
            session.bulk_save_objects(batch)
            total_inserted += len(batch)
            
            if (i + batch_size) % 10000 == 0:
                logger.debug(f"Inserted {total_inserted} models...")
        
        session.commit()
        logger.info(f"Bulk inserted {total_inserted} model instances")
        
        return total_inserted
        
    except Exception as e:
        session.rollback()
        logger.error(f"Bulk insert failed: {e}")
        raise DatabaseError(
            "bulk_insert_models",
            "Failed to bulk insert model instances",
            {"error": str(e), "model_count": len(models)}
        )


def bulk_delete_by_scan_id(
    session: Session,
    model_class: Type[T],
    scan_id: int
) -> int:
    """
    Bulk delete records for a specific scan.
    
    Args:
        session: SQLAlchemy session
        model_class: ORM model class
        scan_id: Scan ID to delete records for
        
    Returns:
        Number of records deleted
        
    Raises:
        DatabaseError: If bulk delete fails
    """
    try:
        result = session.query(model_class).filter(
            model_class.scan_id == scan_id
        ).delete()
        session.commit()
        
        logger.info(f"Bulk deleted {result} {model_class.__tablename__} records for scan {scan_id}")
        return result
        
    except Exception as e:
        session.rollback()
        logger.error(f"Bulk delete failed: {e}")
        raise DatabaseError(
            "bulk_delete",
            f"Failed to bulk delete {model_class.__tablename__} records",
            {"error": str(e), "scan_id": scan_id}
        )


class BatchInserter:
    """
    Context manager for batched inserts.
    
    Accumulates records and flushes them in batches for better performance.
    
    Example:
        >>> with BatchInserter(session, BanditResult, batch_size=500) as inserter:
        ...     for record in records:
        ...         inserter.add(record)
    """
    
    def __init__(
        self,
        session: Session,
        model_class: Type[T],
        batch_size: int = 1000
    ):
        """
        Initialize batch inserter.
        
        Args:
            session: SQLAlchemy session
            model_class: ORM model class
            batch_size: Batch size for inserts
        """
        self.session = session
        self.model_class = model_class
        self.batch_size = batch_size
        self.buffer: List[T] = []
        self.total_inserted = 0
    
    def add(self, model: T):
        """
        Add model to buffer.
        
        Automatically flushes when buffer reaches batch size.
        
        Args:
            model: ORM model instance
        """
        self.buffer.append(model)
        if len(self.buffer) >= self.batch_size:
            self.flush()
    
    def flush(self):
        """Flush buffer to database."""
        if not self.buffer:
            return
        
        try:
            self.session.bulk_save_objects(self.buffer)
            self.session.commit()
            self.total_inserted += len(self.buffer)
            logger.debug(f"Flushed {len(self.buffer)} records (total: {self.total_inserted})")
            self.buffer.clear()
        except Exception as e:
            self.session.rollback()
            logger.error(f"Flush failed: {e}")
            raise DatabaseError(
                "batch_flush",
                "Failed to flush batch to database",
                {"error": str(e), "buffer_size": len(self.buffer)}
            )
    
    def __enter__(self):
        """Enter context manager."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context manager and flush remaining records."""
        if exc_type is None:
            self.flush()
        else:
            self.session.rollback()
        
        logger.info(f"BatchInserter completed: {self.total_inserted} total records inserted")
        return False
