# Copyright (c) 2025 Anush Krishna
# Licensed under the MIT License. See LICENSE file in the project root.

from __future__ import annotations

"""Configuration schema definitions using Pydantic.

This module defines the data models for application configuration including
database settings, tool configurations, and logging options.

Classes
-------
Config : Main configuration class
DatabaseConfig : Database configuration
ToolsConfig : Tool-specific configuration
LoggingConfig : Logging configuration
DashboardConfig : Dashboard configuration

Examples
--------
>>> config = Config(database_url="sqlite:///audit.db")
>>> config.validate()

See Also
--------
auditor.config.config_loader : Configuration loading
"""

"""
Configuration schema and validation for CodeQAuditor.

This module defines the configuration structure, default values, and
validation logic for all application settings.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any
import os


@dataclass
class ProjectConfig:
    """Configuration for project paths and structure."""
    
    root: str = "."
    output_dir: str = "out"
    exclude_patterns: List[str] = field(default_factory=lambda: [
        "*.pyc",
        "__pycache__",
        "venv",
        ".venv",
        "node_modules",
        ".git",
        "*.egg-info",
        "dist",
        "build"
    ])
    
    def validate(self) -> List[str]:
        """
        Validate project configuration.
        
        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []
        
        root_path = Path(self.root)
        if not root_path.exists():
            errors.append(f"Project root does not exist: {self.root}")
        elif not root_path.is_dir():
            errors.append(f"Project root is not a directory: {self.root}")
        
        return errors


@dataclass
class ToolsConfig:
    """Configuration for static analysis tools."""
    
    enabled: List[str] = field(default_factory=lambda: [
        "bandit",
        "mypy",
        "radon",
        "vulture",
        "eslint",
        "semgrep"
    ])
    parallel: bool = True
    max_workers: Optional[int] = None
    timeout: int = 300  # seconds
    
    # Tool-specific configurations
    bandit_config: Optional[str] = None
    mypy_config: Optional[str] = None
    eslint_config: Optional[str] = None
    semgrep_config: Optional[str] = None
    
    def validate(self) -> List[str]:
        """
        Validate tools configuration.
        
        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []
        
        valid_tools = {"bandit", "mypy", "radon", "vulture", "eslint", "semgrep"}
        for tool in self.enabled:
            if tool not in valid_tools:
                errors.append(f"Unknown tool: {tool}")
        
        if self.max_workers is not None and self.max_workers < 1:
            errors.append(f"max_workers must be >= 1, got {self.max_workers}")
        
        if self.timeout < 1:
            errors.append(f"timeout must be >= 1, got {self.timeout}")
        
        return errors


@dataclass
class DatabaseConfig:
    """Configuration for database operations."""
    
    path: str = "out/auditor.db"
    echo: bool = False
    pool_size: int = 5
    max_overflow: int = 10
    pool_timeout: int = 30
    
    def validate(self) -> List[str]:
        """
        Validate database configuration.
        
        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []
        
        db_path = Path(self.path)
        db_dir = db_path.parent
        
        if not db_dir.exists():
            try:
                db_dir.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                errors.append(f"Cannot create database directory: {e}")
        
        if self.pool_size < 1:
            errors.append(f"pool_size must be >= 1, got {self.pool_size}")
        
        return errors


@dataclass
class LoggingConfig:
    """Configuration for logging."""
    
    level: str = "INFO"
    file: str = "logs/auditor.log"
    console: bool = True
    file_output: bool = True
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    max_bytes: int = 10 * 1024 * 1024  # 10 MB
    backup_count: int = 5
    
    def validate(self) -> List[str]:
        """
        Validate logging configuration.
        
        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []
        
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if self.level.upper() not in valid_levels:
            errors.append(f"Invalid log level: {self.level}")
        
        if self.max_bytes < 1024:
            errors.append(f"max_bytes too small: {self.max_bytes}")
        
        if self.backup_count < 0:
            errors.append(f"backup_count must be >= 0, got {self.backup_count}")
        
        return errors


@dataclass
class DashboardConfig:
    """Configuration for the dashboard."""
    
    host: str = "127.0.0.1"
    port: int = 8050
    debug: bool = False
    theme: str = "light"
    
    def validate(self) -> List[str]:
        """
        Validate dashboard configuration.
        
        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []
        
        if self.port < 1 or self.port > 65535:
            errors.append(f"Invalid port number: {self.port}")
        
        if self.theme not in {"light", "dark"}:
            errors.append(f"Invalid theme: {self.theme}")
        
        return errors


@dataclass
class Config:
    """
    Main configuration class for CodeQAuditor.
    
    This class aggregates all configuration sections and provides
    validation and loading functionality.
    """
    
    project: ProjectConfig = field(default_factory=ProjectConfig)
    tools: ToolsConfig = field(default_factory=ToolsConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    
    def validate(self) -> bool:
        """
        Validate entire configuration.
        
        Returns:
            True if valid, raises ConfigurationError if invalid
            
        Raises:
            ConfigurationError: If any validation fails
        """
        from auditor.core.exceptions import ConfigurationError
        
        all_errors = []
        
        # Validate each section
        all_errors.extend(self.project.validate())
        all_errors.extend(self.tools.validate())
        all_errors.extend(self.database.validate())
        all_errors.extend(self.logging.validate())
        all_errors.extend(self.dashboard.validate())
        
        if all_errors:
            error_msg = "\n".join(f"  - {err}" for err in all_errors)
            raise ConfigurationError(
                "configuration",
                f"Configuration validation failed:\n{error_msg}",
                {"errors": all_errors}
            )
        
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert configuration to dictionary.
        
        Returns:
            Dictionary representation of configuration
        """
        return {
            "project": self.project.__dict__,
            "tools": self.tools.__dict__,
            "database": self.database.__dict__,
            "logging": self.logging.__dict__,
            "dashboard": self.dashboard.__dict__,
        }
    
    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> 'Config':
        """
        Create configuration from dictionary.
        
        Args:
            config_dict: Dictionary with configuration values
            
        Returns:
            Config instance
        """
        return cls(
            project=ProjectConfig(**config_dict.get("project", {})),
            tools=ToolsConfig(**config_dict.get("tools", {})),
            database=DatabaseConfig(**config_dict.get("database", {})),
            logging=LoggingConfig(**config_dict.get("logging", {})),
            dashboard=DashboardConfig(**config_dict.get("dashboard", {})),
        )


def get_default_config() -> Config:
    """
    Get default configuration.
    
    Returns:
        Config instance with default values
    """
    return Config()
