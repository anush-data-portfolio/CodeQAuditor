from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv


@dataclass(frozen=True, slots=True)
class AppConfig:
    """Strongly-typed application configuration."""

    node_tools_cache: Path
    database_url: str
    gitignore_path: Path


def _normalize_path(raw: str, *, allow_none: bool = False) -> Optional[Path]:
    if raw is None:
        return None
    raw = raw.strip()
    if not raw:
        if allow_none:
            return None
        raise ValueError("Expected a non-empty path string.")
    return Path(raw).expanduser().resolve()


def _require_env(name: str) -> str:
    value = os.getenv(name)
    if value is None or not value.strip():
        raise RuntimeError(f"Environment variable '{name}' is required but missing.")
    return value.strip()


def load_config(dotenv_path: str | Path | None = None, *, override: bool = False) -> AppConfig:
    """
    Load application configuration from environment variables.

    Parameters
    ----------
    dotenv_path:
        Optional custom .env file location.  When omitted python-dotenv falls back to the default search.
    override:
        When True, environment values already present will be overridden by the ones defined in the .env file.
    """
    load_dotenv(dotenv_path, override=override)

    node_tools_raw = os.getenv("NODE_TOOLS_CACHE")
    database_url = _require_env("DATABASE_URL")
    gitignore_raw = _require_env("GITIGNORE_PATH")

    node_tools_path = (
        _normalize_path(node_tools_raw, allow_none=True)
        if node_tools_raw is not None
        else Path.cwd() / "node_tools"
    )
    gitignore_path = _normalize_path(gitignore_raw)

    return AppConfig(
        node_tools_cache=node_tools_path,
        database_url=database_url,
        gitignore_path=gitignore_path,
    )


__all__ = ["AppConfig", "load_config"]

CONFIG = load_config()
