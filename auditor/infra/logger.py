"""
Centralized logging configuration for CodeQAuditor.

This module sets up structured logging with file output, rotation,
and configurable log levels.
"""

import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Optional


_LOGGING_CONFIGURED = False


def setup_logging(
    log_level: str = "INFO",
    log_file: Optional[Path] = None,
    console: bool = True
) -> logging.Logger:
    """
    Configure logging for the application.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file. If None, uses logs/auditor.log
        console: Whether to also log to console
        
    Returns:
        Configured root logger
    """
    global _LOGGING_CONFIGURED
    
    if _LOGGING_CONFIGURED:
        return logging.getLogger()
    
    # Create logs directory
    if log_file is None:
        log_file = Path("logs/auditor.log")
    log_file.parent.mkdir(exist_ok=True, parents=True)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper()))
    
    # Remove existing handlers
    root_logger.handlers.clear()
    
    # Log format
    formatter = logging.Formatter(
        fmt='%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # File handler with rotation (10MB max, keep 5 backups)
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)  # Log everything to file
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)
    
    # Console handler (if enabled)
    if console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(getattr(logging, log_level.upper()))
        
        # Simpler format for console
        console_formatter = logging.Formatter(
            fmt='%(levelname)s: %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)
    
    _LOGGING_CONFIGURED = True
    return root_logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger for a specific module.
    
    Args:
        name: Logger name (typically __name__)
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)
