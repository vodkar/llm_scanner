from pathlib import Path
from typing import Any, LiteralString

from pydantic import BaseModel, ConfigDict

from clients.neo4j import Neo4jClient
from models.base import NodeID
from models.context import CodeContextNode
from repositories.base import ensure_core_indexes
from repositories.queries import (
    code_bfs_nodes_batch_query,
    code_bfs_nodes_query,
    code_nodes_by_file_line_query,
    code_traversal_relationship_types,
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
        ensure_core_indexes(self.client)

        configured_types = code_traversal_relationship_types()
        rows = self.client.run_read(RELATIONSHIP_TYPES_QUERY)
        available_types: set[str] = {
            str(row.get("relationshipType", "")) for row in rows if row.get("relationshipType")
        }
        self.traversal_relationship_types = tuple(
            rel_type for rel_type in configured_types if rel_type in available_types
        )

    def fetch_code_nodes_by_file_lines(
        self,
        rows: list[dict[str, object]],
    ) -> list[CodeContextNode]:
        """Return code nodes containing the supplied file/line pairs.

        Args:
            rows: Items with ``file_path`` and ``line_number`` keys.

        Returns:
            Matching code nodes.
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
        return self._build_context_nodes(self.client.run_read(query, {"rows": normalized_rows}))

    def fetch_code_neighborhood_batch(
        self, start_node_ids: list[str], max_depth: int
    ) -> list[CodeContextNode]:
        """Return BFS expansion of code nodes from multiple start nodes.

        Args:
            start_node_ids: Identifiers of code nodes to start from.
            max_depth: Maximum traversal depth.

        Returns:
            Neighboring code nodes with traversal depth.
        """

        if not start_node_ids:
            return []

        unique_start_ids: tuple[str, ...] = tuple(sorted(set(start_node_ids)))
        # cache_key = (max_depth, unique_start_ids)

        # with self._cache_lock:
        #     cached_rows = self._neighborhood_cache.get(cache_key)
        # if cached_rows is not None:
        #     return self._build_context_nodes(cached_rows)

        if len(unique_start_ids) == 1:
            query = code_bfs_nodes_query(max_depth, self.traversal_relationship_types)
            rows = self.client.run_read(
                query,
                {
                    "start_id": unique_start_ids[0],
                    "max_depth": max_depth,
                },
            )

        else:
            query = code_bfs_nodes_batch_query(max_depth, self.traversal_relationship_types)
            rows = self.client.run_read(
                query,
                {
                    "start_ids": list(unique_start_ids),
                    "max_depth": max_depth,
                },
            )

        # with self._cache_lock:
        #     if len(self._neighborhood_cache) >= self.neighborhood_cache_max_entries:
        #         self._neighborhood_cache.clear()
        # self._neighborhood_cache[cache_key] = rows

        return self._build_context_nodes(rows)

    def _build_context_nodes(self, rows: list[dict[str, Any]]) -> list[CodeContextNode]:
        """Convert Neo4j rows into context nodes.

        Args:
            rows: Neo4j rows for code nodes.

        Returns:
            Unique context nodes preserving first-seen order, shallowest depth,
            and duplicate counts.
        """

        nodes_by_id: dict[NodeID, CodeContextNode] = {}
        ordered_node_ids: list[NodeID] = []

        for row in rows:
            node_id = NodeID(str(row["id"]))
            row_depth = int(row.get("depth", 0))
            if node_id in nodes_by_id:
                existing_node = nodes_by_id[node_id]
                existing_node.repeats += 1
                existing_node.depth = min(existing_node.depth, row_depth)
                continue

            nodes_by_id[node_id] = CodeContextNode(
                identifier=node_id,
                node_kind=self._coerce_str(row.get("node_kind")),
                name=self._coerce_str(row.get("name")),
                file_path=Path(str(row.get("node_file_path") or row.get("file_path", ""))),
                line_start=int(row["line_start"]),
                line_end=int(row["line_end"]),
                depth=row_depth,
                finding_evidence_score=float(row.get("finding_evidence_score") or 0.0),
                security_path_score=float(row.get("security_path_score") or 0.0),
            )
            ordered_node_ids.append(node_id)

        return [nodes_by_id[node_id] for node_id in ordered_node_ids]

    @staticmethod
    def _coerce_str(value: Any | None) -> str | None:
        """Convert a value to string when possible."""

        if value is None:
            return None
        return str(value)
