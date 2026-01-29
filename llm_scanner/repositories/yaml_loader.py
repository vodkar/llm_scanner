from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, TypedDict

import yaml

from models.base import NodeID
from models.edges import RelationshipBase
from models.nodes import Node
from repositories._serialization import flatten_node_rows

logger = logging.getLogger(__name__)


class _LiteralString(str):
    """Marker type to force YAML literal block style (|) for multi-line strings."""


def _literal_str_representer(dumper: Any, data: _LiteralString) -> object:
    return dumper.represent_scalar("tag:yaml.org,2002:str", str(data), style="|")


yaml.SafeDumper.add_representer(_LiteralString, _literal_str_representer)  # type: ignore[arg-type]


class GraphYAML(TypedDict):
    nodes: list[dict[str, object]]
    edges: list[dict[str, object]]


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

    def _to_serializable(
        self, nodes: dict[NodeID, Node], edges: list[RelationshipBase]
    ) -> GraphYAML:
        """Convert models to plain Python structures suitable for YAML dumping."""
        node_rows = flatten_node_rows(nodes)
        for row in node_rows:
            code_val = row.get("code")
            if isinstance(code_val, str) and ("\n" in code_val or "\r" in code_val):
                row["code"] = _LiteralString(code_val)

        edge_rows: list[dict[str, object]] = []
        for rel in edges:
            edge_payload: dict[str, object] = rel.model_dump(mode="json")
            if "type" not in edge_payload:
                edge_payload["type"] = rel.__class__.__name__
            if "kind" not in edge_payload:
                edge_payload["kind"] = rel.__class__.__name__
            edge_rows.append(edge_payload)

        graph_payload: GraphYAML = {"nodes": node_rows, "edges": edge_rows}
        return graph_payload

    def load(self, nodes: dict[NodeID, Node], edges: list[RelationshipBase]) -> None:
        """Write nodes and edges to the configured YAML file.

        Args:
            nodes: Mapping of node id to Node model.
            edges: List of relationship models connecting nodes.
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
