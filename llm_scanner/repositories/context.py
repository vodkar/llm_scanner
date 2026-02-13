from typing import Any

from pydantic import BaseModel, ConfigDict

from clients.neo4j import Neo4jClient
from repositories.queries import code_bfs_nodes_query, finding_reported_code_query


class ContextRepository(BaseModel):
    """Read-only repository for assembling LLM context from Neo4j."""

    client: Neo4jClient
    model_config = ConfigDict(arbitrary_types_allowed=True)

    def fetch_reported_code_nodes(self, finding_ids: list[str]) -> list[dict[str, object]]:
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

    def fetch_code_neighborhood(self, start_node_id: str, max_depth: int) -> list[dict[str, Any]]:
        """Return BFS expansion of code nodes from a start node.

        Args:
            start_node_id: Identifier of the code node to start from.
            max_depth: Maximum traversal depth.

        Returns:
            Rows describing neighboring code nodes with depth metadata.
        """

        query = code_bfs_nodes_query()
        return self.client.run_read(
            query,
            {
                "start_id": start_node_id,
                "max_depth": max_depth,
            },
        )
