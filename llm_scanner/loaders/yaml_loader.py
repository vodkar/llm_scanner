from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, TypedDict

import yaml
from models.edge import Edge
from models.node import Node

logger = logging.getLogger(__name__)


class _LiteralString(str):
    """Marker type to force YAML literal block style (|) for multi-line strings."""


def _literal_str_representer(dumper: yaml.SafeDumper, data: _LiteralString):  # type: ignore[name-defined]
    return dumper.represent_scalar("tag:yaml.org,2002:str", str(data), style="|")


yaml.SafeDumper.add_representer(_LiteralString, _literal_str_representer)  # type: ignore[arg-type]


class EdgeRow(TypedDict):
    src: str
    dst: str
    type: str


class GraphYAML(TypedDict):
    nodes: list[dict[str, object]]
    edges: List[EdgeRow]


class YamlLoader:
    """Persist a Code Property Graph as YAML.

    The output YAML schema mirrors the JSON loader:
    - nodes: list of node dictionaries
    - edges: list of edge dictionaries

    Multi-line fields like node.code are emitted using YAML literal blocks (|)
    for readability.
    """

    def __init__(self, output_path: str | Path, indent: int = 2) -> None:
        """Create a YAML loader.

        Args:
            output_path: Target file path to write the YAML graph into.
            indent: Indentation level for pretty-printing YAML.
        """
        self.output_path: Path = Path(output_path)
        self.indent: int = indent

    def _to_serializable(self, nodes: Dict[str, Node], edges: List[Edge]) -> GraphYAML:
        """Convert models to plain Python structures suitable for YAML dumping."""
        node_rows: list[dict[str, object]] = []
        for n in nodes.values():
            row = n.model_dump()
            # Force literal block for multi-line code for readability
            code_val = row.get("code")
            if isinstance(code_val, str) and ("\n" in code_val or "\r" in code_val):
                row["code"] = _LiteralString(code_val)
            # Ensure enum-like fields are plain strings for YAML
            if "type" in row:
                row["type"] = str(row["type"])  # pydantic may already be str; safe cast
            node_rows.append(row)

        edge_rows: list[EdgeRow] = [
            {"src": e.src, "dst": e.dst, "type": str(e.type)} for e in edges
        ]

        payload: GraphYAML = {"nodes": node_rows, "edges": edge_rows}
        return payload

    def load(self, nodes: Dict[str, Node], edges: List[Edge]) -> None:
        """Write nodes and edges to the configured YAML file.

        Args:
            nodes: Mapping of node id to Node model.
            edges: List of Edge models connecting nodes.
        """
        if self.output_path.parent and not self.output_path.parent.exists():
            self.output_path.parent.mkdir(parents=True, exist_ok=True)

        payload = self._to_serializable(nodes, edges)

        try:
            with self.output_path.open("w", encoding="utf-8") as f:
                yaml.safe_dump(
                    payload,
                    f,
                    allow_unicode=True,
                    sort_keys=False,
                    default_flow_style=False,
                    indent=self.indent,
                    width=4096,  # avoid line folding for readability
                )
        except OSError:
            logger.exception("Failed to write CPG YAML to %s", self.output_path)
            raise
