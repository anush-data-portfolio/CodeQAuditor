# Copyright (c) 2025 Anush Krishna
# Licensed under the MIT License. See LICENSE file in the project root.

from __future__ import annotations

"""Configuration management for CodeQAuditor.

This package handles application configuration loading from multiple sources
including files, environment variables, and defaults.

Modules
-------
config_loader : Configuration loading utilities
config_schema : Configuration data models

Examples
--------
>>> from auditor.config import ConfigLoader
>>> loader = ConfigLoader()
>>> config = loader.load_config("config.yaml")

See Also
--------
auditor.core.exceptions : Configuration errors
"""

"""
Configuration package for CodeQAuditor.

This package provides configuration management functionality including
schema definition, validation, and loading from multiple sources.
"""

from .config_schema import (
    Config,
    ProjectConfig,
    ToolsConfig,
    DatabaseConfig,
    LoggingConfig,
    DashboardConfig,
    get_default_config,
)
from .config_loader import ConfigLoader, load_config

__all__ = [
    'Config',
    'ProjectConfig',
    'ToolsConfig',
    'DatabaseConfig',
    'LoggingConfig',
    'DashboardConfig',
    'get_default_config',
    'ConfigLoader',
    'load_config',
]
