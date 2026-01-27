from __future__ import annotations

from typing import Mapping

from models.base import NodeID
from models.nodes import Node


def flatten_node_rows(nodes: Mapping[NodeID, Node]) -> list[dict[str, object]]:
    """Flatten structured nodes into dictionaries for file serialization.

    Args:
        nodes: Mapping of node identifiers to structured node instances.

    Returns:
        List of dictionaries that merge the identifier, node kind, and the
        node's own fields for easier persistence.
    """

    rows: list[dict[str, object]] = []
    for node_id, node in nodes.items():
        payload = node.model_dump(mode="json")
        row: dict[str, object] = {"id": str(node_id), "kind": node.__class__.__name__}
        row.update(payload)
        rows.append(row)
    return rows


def graph_node_rows(nodes: Mapping[NodeID, Node]) -> list[dict[str, object]]:
    """Build property rows used by graph repositories.

    Args:
        nodes: Mapping of node identifiers to structured node instances.

    Returns:
        List of dictionaries with metadata and attribute maps for ingestion by
        Neo4j or other graph stores.
    """

    rows: list[dict[str, object]] = []
    for node_id, node in nodes.items():
        payload = node.model_dump(mode="json")
        rows.append(
            {
                "id": node_id,
                "node_kind": node.__class__.__name__,
                "name": payload.get("name"),
                "file_path": str(node.file_path),
                "attrs": payload,
            }
        )
    return rows
