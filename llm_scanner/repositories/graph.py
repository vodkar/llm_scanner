from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import re
from typing import Final

from clients.neo4j import Neo4jClient
from repositories._serialization import graph_node_rows
from repositories.queries import (
    NODE_QUERY_BY_LABEL,
    RELATIONSHIP_QUERY_BY_TYPE,
    is_supported_relationship_type,
)
from models.bandit_report import BanditReport
from repositories.dlint_report import DlintReport
from models.edges import RelationshipBase
from models.nodes import Node
from models.base import NodeID


RELATIONSHIP_TYPE_PATTERN: re.Pattern[str] = re.compile(r"^[A-Z][A-Z0-9_]*$")
DEFAULT_RELATIONSHIP_TYPE: Final[str] = "USED_IN"
NODE_KIND_TO_LABEL: Final[dict[str, str]] = {
    "FunctionNode": "Function",
    "ClassNode": "Class",
    "CodeBlockNode": "CodeBlock",
    "ModuleNode": "Module",
    "VariableNode": "Variable",
    "CallNode": "Call",
}


class GraphRepository(Neo4jClient):
    """Persist CPG nodes and relationships into Neo4j."""

    def __init__(self, client: Neo4jClient) -> None:
        self.client = client
        self._ensure_indexes()

    def _ensure_indexes(self) -> None:
        """Ensure core indexes are available for graph ingestion."""

        # self.client.run_write("CREATE INDEX IF NOT EXISTS FOR (n:Code) ON (n.id)")

    def _clear_database(self) -> None:
        """Remove existing graph data before loading new data."""

        self.client.run_write("MATCH (n) DETACH DELETE n")

    @staticmethod
    def _camel_to_upper_snake(value: str) -> str:
        """Convert CamelCase values to UPPER_SNAKE_CASE.

        Args:
            value: Input string in CamelCase or PascalCase.

        Returns:
            Converted string in UPPER_SNAKE_CASE.
        """

        step_one = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
        step_two = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", step_one)
        return re.sub(r"[^A-Za-z0-9_]", "_", step_two).upper()

    def _relationship_type_for_edge(self, rel_type: str | None) -> str:
        """Resolve a Neo4j relationship type for an edge.

        Args:
            rel_type: Raw relationship type or class name.

        Returns:
            Valid Neo4j relationship type.
        """

        if not rel_type:
            return DEFAULT_RELATIONSHIP_TYPE
        rel_type = rel_type.strip()
        if RELATIONSHIP_TYPE_PATTERN.fullmatch(rel_type):
            return rel_type
        candidate = self._camel_to_upper_snake(rel_type)
        if RELATIONSHIP_TYPE_PATTERN.fullmatch(candidate):
            return candidate
        return DEFAULT_RELATIONSHIP_TYPE

    def load(self, nodes: dict[NodeID, Node], edges: list[RelationshipBase]) -> None:
        """Load nodes and relationships into Neo4j.

        Args:
            nodes: Mapping of node identifiers to node models.
            edges: Relationships connecting nodes.
        """

        self._clear_database()
        node_rows = graph_node_rows(nodes)
        nodes_by_label: dict[str, list[dict[str, object]]] = defaultdict(list)
        for row in node_rows:
            node_kind = str(row["node_kind"])
            label = NODE_KIND_TO_LABEL[node_kind]
            nodes_by_label[label].append(row)

        for label, rows in nodes_by_label.items():
            query_nodes = NODE_QUERY_BY_LABEL[label]
            self.client.run_write(query_nodes, {"rows": rows})

        edge_rows_by_type: dict[str, list[dict[str, object]]] = defaultdict(list)
        for rel in edges:
            payload: dict[str, object] = rel.model_dump(mode="json")
            rel_type_raw = payload.get("type")
            if rel_type_raw is None:
                rel_type_raw = rel.__class__.__name__
                payload["type"] = rel_type_raw

            rel_type = self._relationship_type_for_edge(str(rel_type_raw))
            query_type = (
                rel_type
                if is_supported_relationship_type(rel_type)
                else DEFAULT_RELATIONSHIP_TYPE
            )

            attrs = dict(payload)
            attrs.pop("src", None)
            attrs.pop("dst", None)

            edge_rows_by_type[query_type].append(
                {
                    "src": str(payload.get("src")),
                    "dst": str(payload.get("dst")),
                    "type": rel_type,
                    "attrs": attrs,
                }
            )

        for rel_type, rows in edge_rows_by_type.items():
            query_edges = RELATIONSHIP_QUERY_BY_TYPE[rel_type]
            self.client.run_write(query_edges, {"rows": rows})

    def get_nodes_by_file_and_line_numbers(
        self, file_line_numbers: dict[Path, list[int]]
    ) -> dict[Path, dict[int, Node]]:
        return {}
