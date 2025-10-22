# auditor/tools/madge.py
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Iterable

from ..base import AuditTool, Finding, ToolRunResult
from .nodejs import NodeToolMixin


class MadgeTool(AuditTool, NodeToolMixin):
    """
    Madge: dependency graph analysis for JS/TS projects.
    Emits:
      - circular dependency cycles (issue, architecture)
      - orphan modules (analysis, deadcode)
    """

    @property
    def name(self) -> str:
        return "madge"

    def __init__(
        self,
        tsconfig: Optional[str] = None,
        extensions: Optional[List[str]] = None,  # ["ts","tsx","js","jsx"]
        include_orphans: bool = True,
        include_circular: bool = True,
        external_exclude: Optional[List[str]] = None,  # regexes for external pkgs
        extra_args: Optional[List[str]] = None,
        package_version: Optional[str] = None,        # e.g., "^6"
        **kw: Any,
    ) -> None:
        super().__init__(**kw)
        self.tsconfig = tsconfig
        self.extensions = extensions or ["ts", "tsx", "js", "jsx"]
        self.include_orphans = include_orphans
        self.include_circular = include_circular
        self.external_exclude = external_exclude or []
        self.extra_args = extra_args or []
        self.package_version = package_version

    def build_cmd(self, path: str) -> List[str]:
        cwd = Path(path).resolve()
        cmd = self._node_cmd(
            cwd=cwd,
            exe="madge",
            npm_package="madge",
            version=self.package_version,
            extra=["--json", "--extensions", ",".join(self.extensions)],
        )
        if self.tsconfig:
            cmd += ["--ts-config", self.tsconfig]
        if self.include_orphans:
            cmd.append("--orphans")
        if self.include_circular:
            cmd.append("--circular")
        for pat in self.external_exclude:
            cmd += ["--exclude", pat]
        cmd += self.extra_args
        cmd.append(".")
        return cmd

    # ------------------------ helpers ------------------------

    def _emit_cycle(self, findings: List[Finding], seq: List[str]) -> None:
        if not seq:
            return
        findings.append(
            Finding(
                name="madge.circular",
                tool=self.name,
                rule_id="circular",
                message=f"Circular dependency: {' -> '.join(seq)}",
                file=seq[0],
                line=None,
                col=None,
                extra={"cycle": seq},
                kind="issue",
                category="architecture",
                tags=["madge", "circular-dependency"],
                metrics={"cycle_length": float(len(seq))},
            )
        )

    def _emit_orphan(self, findings: List[Finding], orphan: str) -> None:
        findings.append(
            Finding(
                name="madge.orphan",
                tool=self.name,
                rule_id="orphan",
                message=f"Orphan module (no incoming deps): {orphan}",
                file=orphan,
                line=None,
                col=None,
                extra=None,
                kind="analysis",
                category="deadcode",
                tags=["madge", "orphan"],
                metrics={"count": 1.0},
            )
        )

    def _orphans_from_graph(self, graph: Dict[str, Iterable[str]]) -> List[str]:
        nodes: set[str] = set(graph.keys())
        incoming: set[str] = set()
        for _src, deps in graph.items():
            for d in deps or []:
                incoming.add(str(d))
        return sorted(n for n in nodes if n not in incoming)

    # ------------------------- parse -------------------------

    def parse(self, result: ToolRunResult) -> List[Finding]:
        findings: List[Finding] = []

        # Load JSON; Madge can return dict OR list.
        try:
            data = result.parsed_json
            if data is None:
                data = json.loads(result.stdout or "{}")
        except Exception:
            data = {}

        circular_count = 0
        orphan_count = 0

        # Case A: data is a DICT (may be {graph, circular, orphans} OR pure graph)
        if isinstance(data, dict):
            graph = None

            # circular
            if self.include_circular:
                cycles = data.get("circular")
                if isinstance(cycles, list):
                    for cyc in cycles:
                        if isinstance(cyc, list):
                            self._emit_cycle(findings, [str(x) for x in cyc])
                            circular_count += 1

            # orphans
            if self.include_orphans:
                orphans = data.get("orphans")
                if isinstance(orphans, list):
                    for o in orphans:
                        self._emit_orphan(findings, str(o))
                        orphan_count += 1

            # if no explicit circular/orphans, see if this looks like a pure graph
            if not circular_count and not orphan_count:
                # Some madge versions emit the module graph directly (or under "graph")
                maybe_graph = data.get("graph") if "graph" in data else data
                if isinstance(maybe_graph, dict) and all(
                    isinstance(v, (list, tuple)) for v in maybe_graph.values()
                ):
                    graph = maybe_graph

            if graph and self.include_orphans:
                for o in self._orphans_from_graph(graph):
                    self._emit_orphan(findings, o)
                    orphan_count += 1

        # Case B: data is a LIST
        elif isinstance(data, list):
            # Heuristic: list[str] → orphans, list[list[str]] → cycles
            if data and all(isinstance(x, str) for x in data):
                if self.include_orphans:
                    for o in data:
                        self._emit_orphan(findings, o)
                        orphan_count += 1
            elif data and all(isinstance(x, (list, tuple)) for x in data):
                if self.include_circular:
                    for cyc in data:
                        self._emit_cycle(findings, [str(x) for x in cyc])
                        circular_count += 1
            # else: unknown list shape → ignore gracefully

        return findings
