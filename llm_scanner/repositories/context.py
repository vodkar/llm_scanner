from typing import Any, LiteralString

from pydantic import BaseModel, ConfigDict

from clients.neo4j import Neo4jClient
from repositories.queries import (
    code_bfs_nodes_batch_query,
    code_bfs_nodes_query,
    code_nodes_by_file_line_query,
    code_traversal_relationship_types,
    finding_reported_code_query,
)

INDEX_QUERIES: tuple[LiteralString, ...] = (
    "CREATE INDEX IF NOT EXISTS FOR (n:Code) ON (n.id)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Code) ON (n.file_path)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Finding) ON (n.id)",
)
RELATIONSHIP_TYPES_QUERY: LiteralString = (
    "CALL db.relationshipTypes() YIELD relationshipType RETURN relationshipType"
)


class ContextRepository(BaseModel):
    """Read-only repository for assembling LLM context from Neo4j."""

    client: Neo4jClient
    traversal_relationship_types: tuple[str, ...] = ()
    model_config = ConfigDict(arbitrary_types_allowed=True)

    def model_post_init(self, __context: Any) -> None:
        """Ensure indexes used by context queries exist."""

        del __context
        for query in INDEX_QUERIES:
            self.client.run_write(query)

        configured_types = code_traversal_relationship_types()
        rows = self.client.run_read(RELATIONSHIP_TYPES_QUERY)
        available_types: set[str] = {
            str(row.get("relationshipType", "")) for row in rows if row.get("relationshipType")
        }
        self.traversal_relationship_types = tuple(
            rel_type for rel_type in configured_types if rel_type in available_types
        )

    def fetch_reported_code_nodes(self, finding_ids: list[str]) -> list[dict[str, Any]]:
        """Return code nodes reported by the provided findings.

        Args:
            finding_ids: List of finding identifiers.

        Returns:
            Rows containing finding and code node metadata.
        """

        if not finding_ids:
            return []

        query = finding_reported_code_query()
        return self.client.run_read(query, {"finding_ids": finding_ids})

    def fetch_code_nodes_by_file_lines(
        self,
        rows: list[dict[str, object]],
    ) -> list[dict[str, Any]]:
        """Return code nodes containing the supplied file/line pairs.

        Args:
            rows: Items with ``file_path`` and ``line_number`` keys.

        Returns:
            Rows containing matching code node metadata.
        """

        if not rows:
            return []

        normalized_rows: list[dict[str, object]] = []
        seen_keys: set[tuple[str, int]] = set()
        for row in rows:
            file_path = str(row.get("file_path", ""))
            line_number_raw = row.get("line_number")
            if not file_path or line_number_raw is None:
                continue
            try:
                line_number = int(str(line_number_raw))
            except (TypeError, ValueError):
                continue
            if line_number < 1:
                continue
            key = (file_path, line_number)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            normalized_rows.append(
                {
                    "file_path": file_path,
                    "line_number": line_number,
                }
            )

        if not normalized_rows:
            return []

        query = code_nodes_by_file_line_query()
        return self.client.run_read(query, {"rows": normalized_rows})

    def fetch_code_neighborhood_batch(
        self, start_node_ids: list[str], max_depth: int
    ) -> list[dict[str, Any]]:
        """Return BFS expansion of code nodes from multiple start nodes.

        Args:
            start_node_ids: Identifiers of code nodes to start from.
            max_depth: Maximum traversal depth.

        Returns:
            Rows describing neighboring code nodes with depth and origin start node.
        """

        if not start_node_ids:
            return []

        unique_start_ids = sorted(set(start_node_ids))

        if len(unique_start_ids) == 1:
            query = code_bfs_nodes_query(max_depth, self.traversal_relationship_types)
            return self.client.run_read(
                query,
                {
                    "start_id": unique_start_ids[0],
                    "max_depth": max_depth,
                },
            )

        query = code_bfs_nodes_batch_query(max_depth, self.traversal_relationship_types)
        return self.client.run_read(
            query,
            {
                "start_ids": unique_start_ids,
                "max_depth": max_depth,
            },
        )
