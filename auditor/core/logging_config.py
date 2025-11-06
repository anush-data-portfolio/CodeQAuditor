# Copyright (c) 2025 Anush Krishna
# Licensed under the MIT License. See LICENSE file in the project root.

from __future__ import annotations

"""Logging configuration for the application.

This module provides centralized logging configuration with support for
multiple output formats and log levels.

Functions
---------
setup_logging : Configure application logging

Examples
--------
>>> setup_logging(level="DEBUG")

See Also
--------
auditor.infra.logger : Logger utilities
"""

"""
Logging configuration for CodeQAuditor.

This module provides centralized logging configuration with support for
file and console output, log rotation, and structured logging.
"""

import logging
import logging.handlers
import os
import sys
from pathlib import Path
from typing import Optional


class ColoredFormatter(logging.Formatter):
    """
    Custom formatter that adds color to console output.
    
    Colors are applied based on log level to improve readability.
    """
    
    # ANSI color codes
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
        'RESET': '\033[0m'        # Reset
    }
    
    def format(self, record):
        """Format log record with color codes."""
        if hasattr(sys.stderr, 'isatty') and sys.stderr.isatty():
            levelname = record.levelname
            if levelname in self.COLORS:
                record.levelname = f"{self.COLORS[levelname]}{levelname}{self.COLORS['RESET']}"
        return super().format(record)


def setup_logging(
    log_level: str = "INFO",
    log_file: Optional[str] = None,
    log_dir: str = "logs",
    console_output: bool = True,
    file_output: bool = True,
    max_bytes: int = 10 * 1024 * 1024,  # 10 MB
    backup_count: int = 5
) -> logging.Logger:
    """
    Configure logging for the application.
    
    Sets up both console and file logging with appropriate formatters,
    log rotation, and filtering.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Name of the log file. If None, uses 'auditor.log'
        log_dir: Directory for log files
        console_output: Whether to output logs to console
        file_output: Whether to output logs to file
        max_bytes: Maximum size of log file before rotation
        backup_count: Number of backup files to keep
    
    Returns:
        Configured logger instance
    
    Example:
        >>> logger = setup_logging(log_level='DEBUG', log_file='my_audit.log')
        >>> logger.info('Starting audit...')
    """
    # Create logger
    logger = logging.getLogger('codeqauditor')
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    
    # Remove existing handlers
    logger.handlers.clear()
    
    # Console handler
    if console_output:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_formatter = ColoredFormatter(
            '%(levelname)s: %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
    
    # File handler with rotation
    if file_output:
        # Create log directory if it doesn't exist
        log_path = Path(log_dir)
        log_path.mkdir(parents=True, exist_ok=True)
        
        # Set log file name
        if log_file is None:
            log_file = 'auditor.log'
        
        log_file_path = log_path / log_file
        
        file_handler = logging.handlers.RotatingFileHandler(
            log_file_path,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    # Prevent propagation to root logger
    logger.propagate = False
    
    return logger


def get_logger(name: str = 'codeqauditor') -> logging.Logger:
    """
    Get a logger instance.
    
    Args:
        name: Name of the logger. Use __name__ from calling module.
    
    Returns:
        Logger instance
    
    Example:
        >>> logger = get_logger(__name__)
        >>> logger.info('Processing file...')
    """
    return logging.getLogger(name)


class LogContext:
    """
    Context manager for adding contextual information to logs.
    
    Example:
        >>> with LogContext(logger, file_path='/path/to/file'):
        ...     logger.info('Processing')  # Will include file_path in log
    """
    
    def __init__(self, logger: logging.Logger, **context):
        """
        Initialize log context.
        
        Args:
            logger: Logger instance
            **context: Contextual key-value pairs to include in logs
        """
        self.logger = logger
        self.context = context
        self.old_factory = None
    
    def __enter__(self):
        """Enter context and add contextual information."""
        old_factory = logging.getLogRecordFactory()
        
        def record_factory(*args, **kwargs):
            record = old_factory(*args, **kwargs)
            for key, value in self.context.items():
                setattr(record, key, value)
            return record
        
        self.old_factory = old_factory
        logging.setLogRecordFactory(record_factory)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context and restore original factory."""
        if self.old_factory:
            logging.setLogRecordFactory(self.old_factory)


# Initialize default logger
_default_logger = None


def init_default_logger(log_level: str = "INFO", log_dir: str = "logs"):
    """
    Initialize the default application logger.
    
    This should be called once at application startup.
    
    Args:
        log_level: Logging level
        log_dir: Directory for log files
    """
    global _default_logger
    _default_logger = setup_logging(log_level=log_level, log_dir=log_dir)
    return _default_logger
