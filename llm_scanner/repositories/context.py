from pathlib import Path
from typing import Any, LiteralString

from pydantic import BaseModel, ConfigDict

from clients.neo4j import Neo4jClient
from models.base import NodeID
from models.context import CodeContextNode
from repositories.base import ensure_core_indexes
from repositories.queries import (
    backward_dataflow_taint_query,
    code_bfs_nodes_batch_query,
    code_bfs_nodes_query,
    code_nodes_by_file_span_query,
    code_traversal_relationship_types,
    taint_score_from_hop,
)

RELATIONSHIP_TYPES_QUERY: LiteralString = (
    "CALL db.relationshipTypes() YIELD relationshipType RETURN relationshipType"
)


class ContextRepository(BaseModel):
    """Read-only repository for assembling LLM context from Neo4j."""

    client: Neo4jClient
    traversal_relationship_types: tuple[str, ...] = ()
    # neighborhood_cache_max_entries: int = 1000
    model_config = ConfigDict(arbitrary_types_allowed=True)

    # _cache_lock: Lock = PrivateAttr(default_factory=Lock)
    # _neighborhood_cache: dict[tuple[int, tuple[str, ...]], list[dict[str, Any]]] = PrivateAttr(
    #     default_factory=lambda: cast(dict[tuple[int, tuple[str, ...]], list[dict[str, Any]]], {})
    # )

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

        span_rows: list[dict[str, object]] = []
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
            span_rows.append(
                {
                    "file_path": file_path,
                    "start_line": line_number,
                    "end_line": line_number,
                }
            )

        return self.fetch_code_nodes_by_file_spans(span_rows)

    def fetch_code_nodes_by_file_spans(
        self,
        rows: list[dict[str, object]],
    ) -> list[CodeContextNode]:
        """Return code nodes overlapping the supplied file spans.

        Args:
            rows: Items with ``file_path``, ``start_line``, and ``end_line`` keys.

        Returns:
            Matching code nodes.
        """

        normalized_rows = self._normalize_file_spans(rows)

        if not normalized_rows:
            return []

        query = code_nodes_by_file_span_query()
        return self._build_context_nodes(self.client.run_read(query, {"rows": normalized_rows}))

    @staticmethod
    def _normalize_file_spans(rows: list[dict[str, object]]) -> list[dict[str, object]]:
        """Normalize and merge overlapping file spans.

        Args:
            rows: Candidate file spans.

        Returns:
            Normalized spans with overlaps coalesced per file path.
        """

        spans_by_file: dict[str, list[tuple[int, int]]] = {}
        for row in rows:
            file_path = str(row.get("file_path", ""))
            start_line_raw = row.get("start_line")
            end_line_raw = row.get("end_line")
            if not file_path or start_line_raw is None or end_line_raw is None:
                continue
            try:
                start_line = int(str(start_line_raw))
                end_line = int(str(end_line_raw))
            except (TypeError, ValueError):
                continue
            if start_line < 1 or end_line < start_line:
                continue

            spans_by_file.setdefault(file_path, []).append((start_line, end_line))

        normalized_rows: list[dict[str, object]] = []
        for file_path, spans in spans_by_file.items():
            merged_spans: list[tuple[int, int]] = []
            for start_line, end_line in sorted(spans):
                if not merged_spans:
                    merged_spans.append((start_line, end_line))
                    continue

                previous_start, previous_end = merged_spans[-1]
                if start_line <= previous_end + 1:
                    merged_spans[-1] = (previous_start, max(previous_end, end_line))
                    continue

                merged_spans.append((start_line, end_line))

            normalized_rows.extend(
                {
                    "file_path": file_path,
                    "start_line": start_line,
                    "end_line": end_line,
                }
                for start_line, end_line in merged_spans
            )

        return normalized_rows

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

    def fetch_code_neighborhood_with_edge_paths(
        self, start_node_ids: list[str], max_depth: int
    ) -> list[CodeContextNode]:
        """Return BFS expansion annotated with per-edge-type minimum depths.

        Calls the batch BFS query once per configured edge type and merges
        results by node identifier, populating ``edge_depths`` with the
        shallowest depth at which each node is reachable via each edge type.

        Args:
            start_node_ids: Identifiers of code nodes to start from.
            max_depth: Maximum traversal depth.

        Returns:
            Context nodes with ``edge_depths`` populated when reachable via one
            or more specific edge types; the top-level ``depth`` remains the
            minimum depth across all edge types.
        """

        if not start_node_ids:
            return []

        unique_start_ids: tuple[str, ...] = tuple(sorted(set(start_node_ids)))
        nodes_by_id: dict[NodeID, CodeContextNode] = {}
        ordered_node_ids: list[NodeID] = []

        for edge_type in self.traversal_relationship_types:
            if len(unique_start_ids) == 1:
                query = code_bfs_nodes_query(max_depth, (edge_type,))
                rows = self.client.run_read(
                    query,
                    {"start_id": unique_start_ids[0], "max_depth": max_depth},
                )
            else:
                query = code_bfs_nodes_batch_query(max_depth, (edge_type,))
                rows = self.client.run_read(
                    query,
                    {"start_ids": list(unique_start_ids), "max_depth": max_depth},
                )
            for row in rows:
                node_id = NodeID(str(row["id"]))
                row_depth = int(row.get("depth", 0))
                existing = nodes_by_id.get(node_id)
                if existing is None:
                    depths: dict[str, int] = {edge_type: row_depth}
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
                        edge_depths=depths,
                    )
                    ordered_node_ids.append(node_id)
                    continue

                existing.depth = min(existing.depth, row_depth)
                current_edge_depths = existing.edge_depths or {}
                existing_edge_depth = current_edge_depths.get(edge_type)
                if existing_edge_depth is None or row_depth < existing_edge_depth:
                    current_edge_depths[edge_type] = row_depth
                existing.edge_depths = current_edge_depths

        return [nodes_by_id[node_id] for node_id in ordered_node_ids]

    def fetch_taint_sources(
        self,
        root_node_ids: list[str],
        max_taint_depth: int = 6,
    ) -> dict[NodeID, float]:
        """Return backward-DataFlow taint scores keyed by node ID.

        Traverses FLOWS_TO and DEFINED_BY edges backward from root nodes to
        find variables participating in the data flow reaching the vulnerability.

        Args:
            root_node_ids: Identifiers of root (depth=0) nodes.
            max_taint_depth: Maximum DataFlow hops to traverse backward.

        Returns:
            Mapping of node_id to taint_score for nodes on the backward taint path.
        """
        if not root_node_ids:
            return {}

        unique_root_ids: list[str] = sorted(set(root_node_ids))

        query = backward_dataflow_taint_query(max_taint_depth)
        rows = self.client.run_read(query, {"root_ids": unique_root_ids})
        return {
            NodeID(str(row["id"])): taint_score_from_hop(int(row["taint_hop"]))
            for row in rows
            if row.get("id") is not None
        }

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
