from __future__ import annotations

import logging
import re
from collections import defaultdict
from pathlib import Path
from typing import Final

from clients.neo4j import Neo4jClient
from models.base import NodeID
from models.edges import RelationshipBase
from models.nodes import CodeBlockNode, Node
from repositories._serialization import graph_node_rows
from repositories.queries import (
    NODE_QUERY_BY_LABEL,
    RELATIONSHIP_QUERY_BY_TYPE,
    code_nodes_by_file_line_query,
)

RELATIONSHIP_TYPE_PATTERN: re.Pattern[str] = re.compile(r"^[A-Z][A-Z0-9_]*$")
NODE_KIND_TO_LABEL: Final[dict[str, str]] = {
    "FunctionNode": "Function",
    "ClassNode": "Class",
    "CodeBlockNode": "CodeBlock",
    "ModuleNode": "Module",
    "VariableNode": "Variable",
    "CallNode": "Call",
}

_LOGGER = logging.getLogger(__name__)


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

    def _relationship_type_for_edge(self, rel_type: str) -> str:
        """Resolve a Neo4j relationship type for an edge.

        Args:
            rel_type: Raw relationship type or class name.

        Returns:
            Valid Neo4j relationship type.
        """

        rel_type = rel_type.strip()
        if RELATIONSHIP_TYPE_PATTERN.fullmatch(rel_type):
            return rel_type
        candidate = self._camel_to_upper_snake(rel_type)
        if RELATIONSHIP_TYPE_PATTERN.fullmatch(candidate):
            return candidate
        raise ValueError(f"Unknown relationship type: {rel_type}")

    def load(self, nodes: dict[NodeID, Node], edges: list[RelationshipBase]) -> None:
        """Load nodes and relationships into Neo4j.

        Args:
            nodes: Mapping of node identifiers to node models.
            edges: Relationships connecting nodes.
        """

        self._clear_database()
        _LOGGER.info("Start loading %d nodes and %d edges into Neo4j.", len(nodes), len(edges))
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
            rel_type_raw = payload["type"]
            if rel_type_raw is None:
                rel_type_raw = rel.__class__.__name__
                payload["type"] = rel_type_raw

            rel_type = str(rel_type_raw)
            # rel_type = self._relationship_type_for_edge(str(rel_type_raw))

            attrs = dict(payload)
            attrs.pop("src", None)
            attrs.pop("dst", None)

            edge_rows_by_type[rel_type].append(
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
        """Fetch code nodes that contain specific line numbers in files.

        Args:
            file_line_numbers: Mapping of file paths to line numbers.

        Returns:
            Mapping of file paths to line-number-keyed nodes.
        """

        rows: list[dict[str, object]] = []
        for file_path, line_numbers in file_line_numbers.items():
            if not line_numbers:
                continue
            normalized_path = Path(file_path.as_posix())
            for line_number in sorted(set(line_numbers)):
                rows.append(
                    {
                        "file_path": str(normalized_path),
                        "line_number": int(line_number),
                    }
                )

        if not rows:
            return {}

        query = code_nodes_by_file_line_query()
        result_rows = self.client.run_read(query, {"rows": rows})

        def _coerce_int(value: object | None) -> int:
            if value is None:
                return 0
            try:
                return int(str(value))
            except (TypeError, ValueError):
                return 0

        candidates: dict[tuple[str, int], list[dict[str, object]]] = defaultdict(list)
        for row in result_rows:
            file = str(row.get("file_path", ""))
            line_number = int(row.get("line_number", 0) or 0)
            if not file or line_number <= 0:
                continue
            candidates[(file, line_number)].append(row)

        resolved: dict[Path, dict[int, Node]] = defaultdict(dict)
        for (file, line_number), options in candidates.items():
            sorted_options = sorted(
                options,
                key=lambda opt: (
                    _coerce_int(opt.get("line_end")) - _coerce_int(opt.get("line_start")),
                    str(opt.get("node_kind", "")),
                ),
            )
            chosen = sorted_options[0]
            line_start = _coerce_int(chosen.get("line_start"))
            line_end = _coerce_int(chosen.get("line_end"))
            if line_start <= 0 or line_end <= 0:
                continue
            node = CodeBlockNode(
                identifier=NodeID(str(chosen.get("id"))),
                file_path=Path(str(chosen.get("node_file_path", file))),
                line_start=line_start,
                line_end=line_end,
            )
            resolved[Path(file)][line_number] = node

        return resolved
