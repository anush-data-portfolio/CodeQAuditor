# Copyright (c) 2025 Anush Krishna
# Licensed under the MIT License. See LICENSE file in the project root.

"""Configuration loader for CodeQAuditor.

This module handles loading configuration from multiple sources with
well-defined precedence rules to provide flexible configuration management.

Configuration Sources
---------------------
The loader supports multiple configuration sources with the following priority
order (highest to lowest):

1. Command-line arguments (highest priority)
2. Environment variables (prefixed with CODEQAUDITOR_)
3. Configuration file (YAML or TOML)
4. Default values (lowest priority)

Supported Formats
-----------------
- YAML: .yaml, .yml files
- TOML: .toml files (requires tomli/tomllib)

Environment Variables
---------------------
All environment variables must be prefixed with `CODEQAUDITOR_`. For nested
configuration, use double underscores: `CODEQAUDITOR_DATABASE__URL`

Examples
--------
Load from YAML file:
    >>> loader = ConfigLoader()
    >>> config = loader.load_config('config.yaml')
    >>> config.database_url
    'sqlite:///audit.db'

Load with environment variable override:
    >>> import os
    >>> os.environ['CODEQAUDITOR_DATABASE__URL'] = 'postgresql://...'
    >>> config = loader.load_config('config.yaml')

See Also
--------
config_schema : Configuration schema definitions
"""

import os
import yaml
from pathlib import Path
from typing import Optional, Dict, Any
try:
    import tomli as tomllib
except ImportError:
    try:
        import tomllib
    except ImportError:
        tomllib = None

from .config_schema import Config, ProjectConfig, ToolsConfig, DatabaseConfig, LoggingConfig, DashboardConfig
from auditor.core.exceptions import ConfigurationError


class ConfigLoader:
    """Configuration loader that supports multiple sources.

    This class provides functionality to load configuration from YAML/TOML files
    and merge with environment variables following a defined precedence order.

    Attributes
    ----------
    ENV_PREFIX : str
        Prefix for environment variables ('CODEQAUDITOR_').
    config : Config
        Internal configuration object.

    Notes
    -----
    The loader performs validation during the load process to catch configuration
    errors early. Invalid configurations will raise ConfigurationError.

    Examples
    --------
    Load and validate configuration:
        >>> loader = ConfigLoader()
        >>> config = loader.load_config('config.yaml')
        >>> config.validate()

    Check for specific settings:
        >>> config.database_url
        'sqlite:///data/audit.db'
    """

    ENV_PREFIX = "CODEQAUDITOR_"

    def __init__(self):
        """Initialize configuration loader with default config."""
        self.config = Config()
    
    def load_from_file(self, file_path: str) -> Config:
        """
        Load configuration from a file.
        
        Supports YAML and TOML formats based on file extension.
        
        Args:
            file_path: Path to configuration file
            
        Returns:
            Config instance
            
        Raises:
            ConfigurationError: If file cannot be loaded or parsed
        """
        path = Path(file_path)
        
        if not path.exists():
            raise ConfigurationError(
                "file_path",
                f"Configuration file not found: {file_path}"
            )
        
        try:
            if path.suffix in ['.yaml', '.yml']:
                with open(path, 'r') as f:
                    config_dict = yaml.safe_load(f) or {}
            elif path.suffix == '.toml':
                if tomllib is None:
                    raise ConfigurationError(
                        "toml_support",
                        "TOML support requires 'tomli' package. Install with: pip install tomli"
                    )
                with open(path, 'rb') as f:
                    config_dict = tomllib.load(f)
            else:
                raise ConfigurationError(
                    "file_format",
                    f"Unsupported configuration file format: {path.suffix}"
                )
            
            # Handle nested 'codeqauditor' key if present
            if 'codeqauditor' in config_dict:
                config_dict = config_dict['codeqauditor']
            
            self.config = Config.from_dict(config_dict)
            return self.config
            
        except yaml.YAMLError as e:
            raise ConfigurationError(
                "yaml_parse",
                f"Failed to parse YAML configuration: {e}"
            )
        except Exception as e:
            raise ConfigurationError(
                "file_load",
                f"Failed to load configuration file: {e}"
            )
    
    def load_from_env(self) -> Config:
        """
        Load configuration from environment variables.
        
        Environment variables should be prefixed with CODEQAUDITOR_
        and use double underscores for nesting.
        
        Example:
            CODEQAUDITOR_PROJECT__ROOT=/path/to/project
            CODEQAUDITOR_TOOLS__PARALLEL=true
            CODEQAUDITOR_DATABASE__PATH=/path/to/db.sqlite
        
        Returns:
            Config instance with values from environment
        """
        env_config = {}
        
        for key, value in os.environ.items():
            if key.startswith(self.ENV_PREFIX):
                # Remove prefix and split by double underscore
                config_key = key[len(self.ENV_PREFIX):].lower()
                parts = config_key.split('__')
                
                if len(parts) == 2:
                    section, option = parts
                    if section not in env_config:
                        env_config[section] = {}
                    
                    # Convert string values to appropriate types
                    env_config[section][option] = self._parse_value(value)
        
        if env_config:
            self._merge_config(env_config)
        
        return self.config
    
    def load_from_args(self, args: Dict[str, Any]) -> Config:
        """
        Load configuration from command-line arguments.
        
        Args:
            args: Dictionary of argument names and values
            
        Returns:
            Config instance with values from arguments
        """
        if not args:
            return self.config
        
        # Map command-line args to config structure
        arg_mapping = {
            'root': ('project', 'root'),
            'output_dir': ('project', 'output_dir'),
            'log_level': ('logging', 'level'),
            'log_file': ('logging', 'file'),
            'db_path': ('database', 'path'),
            'parallel': ('tools', 'parallel'),
            'max_workers': ('tools', 'max_workers'),
            'tools': ('tools', 'enabled'),
            'dashboard_port': ('dashboard', 'port'),
            'dashboard_host': ('dashboard', 'host'),
        }
        
        for arg_name, value in args.items():
            if value is not None and arg_name in arg_mapping:
                section, option = arg_mapping[arg_name]
                self._set_config_value(section, option, value)
        
        return self.config
    
    def load_config(
        self,
        config_file: Optional[str] = None,
        env: bool = True,
        args: Optional[Dict[str, Any]] = None
    ) -> Config:
        """
        Load configuration from multiple sources.
        
        Priority order (highest to lowest):
        1. Command-line arguments
        2. Environment variables
        3. Configuration file
        4. Default values
        
        Args:
            config_file: Path to configuration file (optional)
            env: Whether to load from environment variables
            args: Command-line arguments dictionary (optional)
            
        Returns:
            Validated Config instance
            
        Raises:
            ConfigurationError: If configuration is invalid
        """
        # Start with defaults
        self.config = Config()
        
        # Load from file if provided
        if config_file:
            self.load_from_file(config_file)
        
        # Load from environment
        if env:
            self.load_from_env()
        
        # Load from arguments (highest priority)
        if args:
            self.load_from_args(args)
        
        # Validate
        self.config.validate()
        
        return self.config
    
    def _merge_config(self, partial_config: Dict[str, Any]):
        """
        Merge partial configuration into existing config.
        
        Args:
            partial_config: Dictionary with partial configuration
        """
        for section, values in partial_config.items():
            if hasattr(self.config, section):
                section_obj = getattr(self.config, section)
                for key, value in values.items():
                    if hasattr(section_obj, key):
                        setattr(section_obj, key, value)
    
    def _set_config_value(self, section: str, option: str, value: Any):
        """
        Set a single configuration value.
        
        Args:
            section: Configuration section name
            option: Option name within section
            value: Value to set
        """
        if hasattr(self.config, section):
            section_obj = getattr(self.config, section)
            if hasattr(section_obj, option):
                setattr(section_obj, option, value)
    
    @staticmethod
    def _parse_value(value: str) -> Any:
        """
        Parse string value to appropriate type.
        
        Args:
            value: String value from environment variable
            
        Returns:
            Parsed value (bool, int, float, or str)
        """
        # Boolean
        if value.lower() in ('true', '1', 'yes', 'on'):
            return True
        if value.lower() in ('false', '0', 'no', 'off'):
            return False
        
        # Try integer
        try:
            return int(value)
        except ValueError:
            pass
        
        # Try float
        try:
            return float(value)
        except ValueError:
            pass
        
        # Return as string
        return value


def load_config(
    config_file: Optional[str] = None,
    env: bool = True,
    args: Optional[Dict[str, Any]] = None
) -> Config:
    """
    Convenience function to load configuration.
    
    Args:
        config_file: Path to configuration file (optional)
        env: Whether to load from environment variables
        args: Command-line arguments dictionary (optional)
        
    Returns:
        Validated Config instance
    """
    loader = ConfigLoader()
    return loader.load_config(config_file=config_file, env=env, args=args)
