# Copyright (c) 2025 Anush Krishna
# Licensed under the MIT License. See LICENSE file in the project root.

"""Custom exception hierarchy for CodeQAuditor.

This module defines all custom exceptions used throughout the application,
providing a clear error hierarchy for better error handling and debugging.

All exceptions inherit from CodeQAuditorError to allow catching application-specific
errors separately from standard Python exceptions.

Exception Hierarchy
-------------------
CodeQAuditorError (base)
├── ToolExecutionError
├── ParserError
├── DatabaseError
├── ConfigurationError
├── ValidationError
└── FileSystemError

Examples
--------
>>> try:
...     raise ToolExecutionError('bandit', 'Failed to execute')
... except CodeQAuditorError as e:
...     print(f"Tool error: {e.tool_name}")
Tool error: bandit
"""


class CodeQAuditorError(Exception):
    """Base exception for all CodeQAuditor errors.

    All custom exceptions in CodeQAuditor inherit from this class to allow
    catching all application-specific errors with a single except clause.

    Parameters
    ----------
    message : str
        Human-readable error message.
    details : dict, optional
        Dictionary containing additional error context. Default is None.

    Attributes
    ----------
    message : str
        The error message.
    details : dict
        Additional error context information.

    Examples
    --------
    >>> error = CodeQAuditorError("Something went wrong", {"code": 500})
    >>> error.message
    'Something went wrong'
    >>> error.details['code']
    500
    """

    def __init__(self, message: str, details: dict = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ToolExecutionError(CodeQAuditorError):
    """Raised when a static analysis tool fails to execute.

    This exception is raised when tools like bandit, mypy, eslint, etc.
    fail during execution. The details dict contains the tool name and
    any relevant error information like exit codes or stderr output.

    Parameters
    ----------
    tool_name : str
        Name of the tool that failed.
    message : str
        Error message describing the failure.
    details : dict, optional
        Additional error context (exit code, stderr, etc.). Default is None.

    Attributes
    ----------
    tool_name : str
        The name of the failed tool.
    details : dict
        Context including 'tool' key and other diagnostic information.

    Examples
    --------
    >>> error = ToolExecutionError('bandit', 'Command not found')
    >>> error.tool_name
    'bandit'
    >>> error.details['tool']
    'bandit'
    """

    def __init__(self, tool_name: str, message: str, details: dict = None):
        details = details or {}
        details['tool'] = tool_name
        super().__init__(f"Tool '{tool_name}' failed: {message}", details)
        self.tool_name = tool_name


class ParserError(CodeQAuditorError):
    """Raised when parsing tool output fails.

    This exception is raised when the parser cannot correctly process
    the output from a static analysis tool, typically due to unexpected
    format or malformed data.

    Parameters
    ----------
    parser_name : str
        Name of the parser that failed.
    message : str
        Error message describing the parsing failure.
    details : dict, optional
        Additional context (file path, line number, etc.). Default is None.

    Attributes
    ----------
    parser_name : str
        The name of the failed parser.

    Examples
    --------
    >>> error = ParserError('bandit', 'Invalid JSON')
    >>> error.parser_name
    'bandit'
    """

    def __init__(self, parser_name: str, message: str, details: dict = None):
        details = details or {}
        details['parser'] = parser_name
        super().__init__(f"Parser '{parser_name}' failed: {message}", details)
        self.parser_name = parser_name


class DatabaseError(CodeQAuditorError):
    """Raised when database operations fail.

    This exception covers all database-related errors including connection
    issues, query failures, and data integrity problems.

    Parameters
    ----------
    operation : str
        Database operation that failed (e.g., 'insert', 'query', 'update').
    message : str
        Error message describing the database failure.
    details : dict, optional
        Additional context (table name, query, etc.). Default is None.

    Attributes
    ----------
    operation : str
        The database operation that failed.

    Examples
    --------
    >>> error = DatabaseError('insert', 'Duplicate key violation')
    >>> error.operation
    'insert'
    """

    def __init__(self, operation: str, message: str, details: dict = None):
        details = details or {}
        details['operation'] = operation
        super().__init__(f"Database operation '{operation}' failed: {message}", details)
        self.operation = operation


class ConfigurationError(CodeQAuditorError):
    """Raised when there are configuration-related issues.

    This exception is raised for invalid configurations, missing required
    settings, or configuration validation failures.

    Parameters
    ----------
    config_key : str
        Configuration key that caused the error.
    message : str
        Error message describing the configuration issue.
    details : dict, optional
        Additional context. Default is None.

    Attributes
    ----------
    config_key : str
        The problematic configuration key.

    Examples
    --------
    >>> error = ConfigurationError('database_url', 'Invalid URL format')
    >>> error.config_key
    'database_url'
    """

    def __init__(self, config_key: str, message: str, details: dict = None):
        details = details or {}
        details['config_key'] = config_key
        super().__init__(f"Configuration error for '{config_key}': {message}", details)
        self.config_key = config_key


class ValidationError(CodeQAuditorError):
    """Raised when data validation fails.

    This exception is raised when input data or parsed results fail
    validation checks, such as type mismatches or constraint violations.

    Parameters
    ----------
    field : str
        Field that failed validation.
    message : str
        Error message describing the validation failure.
    details : dict, optional
        Additional context. Default is None.

    Attributes
    ----------
    field : str
        The field that failed validation.

    Examples
    --------
    >>> error = ValidationError('line_number', 'Must be positive integer')
    >>> error.field
    'line_number'
    """

    def __init__(self, field: str, message: str, details: dict = None):
        details = details or {}
        details['field'] = field
        super().__init__(f"Validation failed for '{field}': {message}", details)
        self.field = field


class FileSystemError(CodeQAuditorError):
    """Raised when file system operations fail.

    This exception covers file not found, permission denied, and other
    file system related errors during file I/O operations.

    Parameters
    ----------
    path : str
        File or directory path that caused the error.
    message : str
        Error message describing the file system failure.
    details : dict, optional
        Additional context. Default is None.

    Attributes
    ----------
    path : str
        The problematic file or directory path.

    Examples
    --------
    >>> error = FileSystemError('/etc/config', 'Permission denied')
    >>> error.path
    '/etc/config'
    """

    def __init__(self, path: str, message: str, details: dict = None):
        details = details or {}
        details['path'] = path
        super().__init__(f"File system error for '{path}': {message}", details)
        self.path = path
