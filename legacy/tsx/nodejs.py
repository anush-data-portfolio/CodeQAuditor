# auditor/tools/tsx/nodejs.py (or wherever your mixin lives)

from pathlib import Path
from typing import Optional
import os


class NodeToolMixin:
    node_prefix: Optional[str] = None

    def _node_prefix(self) -> Path:
        # Priority: explicit env → ctor param → project root (repo root) → fallback
        env = os.getenv("AUDITOR_NODE_PREFIX")
        if env:
            return Path(env).resolve()

        # If you want a ctor param, store self.node_prefix in __init__ and use it here.
        if getattr(self, "node_prefix", None):
            return Path(self.node_prefix).resolve()

        # Default: project root = two levels up from this file (…/CodeQAuditor)
        return Path(__file__).resolve().parents[3]  # adjust if needed

    def _node_cmd(self, cwd: Path, exe: str, npm_package: str, version: str | None = None,
                  subcommand: list[str] | None = None, extra: list[str] | None = None) -> list[str]:
        prefix = self._node_prefix()
        pkg = npm_package if not version else f"{npm_package}@{version}"
        cmd = ["npx", "--yes", "--prefix", str(prefix), exe]
        if subcommand:
            cmd += subcommand
        if extra:
            cmd += extra
        return cmd
