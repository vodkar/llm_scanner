import logging
from collections import defaultdict
from typing import Final, LiteralString

from clients.neo4j import Neo4jClient
from models.base import NodeID
from models.edges import RelationshipBase
from models.nodes import Node
from repositories._serialization import graph_node_rows
from repositories.base import ensure_core_indexes
from repositories.queries import (
    NODE_QUERY_BY_LABEL,
    RELATIONSHIP_QUERY_BY_TYPE,
)

NODE_KIND_TO_LABEL: Final[dict[str, str]] = {
    "FunctionNode": "Function",
    "ClassNode": "Class",
    "CodeBlockNode": "CodeBlock",
    "ModuleNode": "Module",
    "VariableNode": "Variable",
    "CallNode": "Call",
}

_LOGGER = logging.getLogger(__name__)

NODE_WRITE_BATCH_SIZE: Final[int] = 2_000
EDGE_WRITE_BATCH_SIZE: Final[int] = 2_000


class GraphRepository(Neo4jClient):
    """Persist CPG nodes and relationships into Neo4j."""

    def __init__(self, client: Neo4jClient) -> None:
        self.client = client
        self._ensure_indexes()

    def _ensure_indexes(self) -> None:
        """Ensure core indexes are available for graph ingestion."""

        ensure_core_indexes(self.client)

    def _clear_database(self) -> None:
        """Remove existing graph data before loading new data."""

        self.client.run_write("MATCH (n) DETACH DELETE n")

    def _write_rows_in_batches(
        self,
        query: LiteralString,
        rows: list[dict[str, object]],
        batch_size: int,
    ) -> None:
        """Execute a write query over a large payload in smaller batches.

        Args:
            query: Cypher write query to execute.
            rows: Serialized rows passed as the `rows` parameter.
            batch_size: Maximum number of rows per transaction.
        """

        for start_index in range(0, len(rows), batch_size):
            batch_rows = rows[start_index : start_index + batch_size]
            self.client.run_write(query, {"rows": batch_rows})

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
            self._write_rows_in_batches(query_nodes, rows, NODE_WRITE_BATCH_SIZE)
            _LOGGER.info("Loaded %d nodes with label %s.", len(rows), label)

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
            self._write_rows_in_batches(query_edges, rows, EDGE_WRITE_BATCH_SIZE)
            _LOGGER.info("Loaded %d edges with type %s.", len(rows), rel_type)
