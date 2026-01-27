from __future__ import annotations

import json
import logging
from pathlib import Path

from models.base import NodeID
from models.edges import RelationshipBase
from models.nodes import Node

logger = logging.getLogger(__name__)


def _dot_quote(value: str) -> str:
    """Quote and escape a string for use in DOT source.

    Args:
        value: Raw value.

    Returns:
        A DOT-safe quoted string.
    """

    return json.dumps(value, ensure_ascii=False)


def _format_value(value: object) -> str:
    """Format a value for a DOT label line.

    Args:
        value: Value to format.

    Returns:
        Human-readable representation suitable for embedding into labels.
    """

    if value is None:
        return "null"
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except TypeError:
        return str(value)


def _node_label(*, node_id: NodeID, node: Node) -> str:
    """Build a rich DOT label for a graph node.

    The label is designed to be traceable back to source code.

    Args:
        node_id: Stable node identifier.
        node: Node model instance.

    Returns:
        Multi-line label string.
    """

    kind = node.__class__.__name__
    payload = node.model_dump(mode="json")

    lines: list[str] = [f"kind: {kind}", f"id: {node_id}"]

    name = payload.get("name")
    if isinstance(name, str) and name:
        lines.insert(1, f"name: {name}")

    file_path = payload.get("file_path")
    if isinstance(file_path, str) and file_path:
        lines.append(f"file: {file_path}")

    if "line_number" in payload:
        lines.append(f"line: {_format_value(payload.get('line_number'))}")
    elif "line_start" in payload:
        start = payload.get("line_start")
        end = payload.get("line_end")
        if end is None:
            lines.append(f"line: {_format_value(start)}")
        else:
            lines.append(f"lines: {_format_value(start)}-{_format_value(end)}")

    preferred_order: tuple[str, ...] = (
        "caller_id",
        "callee_id",
        "type_hint",
        "imports",
        "exports",
        "is_entry_point",
        "token_count",
    )
    seen: set[str] = {
        "identifier",
        "name",
        "file_path",
        "line_start",
        "line_end",
        "line_number",
    }

    for key in preferred_order:
        if key in payload and key not in seen:
            lines.append(f"{key}: {_format_value(payload[key])}")
            seen.add(key)

    for key in sorted(payload.keys()):
        if key in seen or key in preferred_order:
            continue
        lines.append(f"{key}: {_format_value(payload[key])}")

    return "\n".join(lines)


def _edge_label(rel: RelationshipBase) -> str:
    """Build a rich DOT label for an edge.

    Args:
        rel: Relationship instance.

    Returns:
        Multi-line label string.
    """

    payload = rel.model_dump(mode="json")
    kind = rel.__class__.__name__
    rel_type = payload.get("type")
    if not isinstance(rel_type, str) or not rel_type:
        rel_type = kind

    lines: list[str] = [f"type: {rel_type}", f"kind: {kind}"]

    for key in sorted(payload.keys()):
        if key in {"src", "dst"}:
            continue
        if key == "type":
            continue
        lines.append(f"{key}: {_format_value(payload[key])}")

    return "\n".join(lines)


class DotLoader:
    """Persist a Code Property Graph as Graphviz DOT.

    This loader writes a DOT file only (no rendering).

    Nodes are labeled with rich traceability information including identifiers and
    source locations (file and line ranges).
    """

    def __init__(self, output_path: str | Path, graph_name: str = "CPG") -> None:
        """Create a DOT loader.

        Args:
            output_path: Target file path to write DOT into.
            graph_name: DOT graph name.
        """

        self.output_path: Path = Path(output_path)
        self.graph_name: str = graph_name

    def _to_dot(self, nodes: dict[NodeID, Node], edges: list[RelationshipBase]) -> str:
        """Convert nodes and edges to DOT source."""

        known_node_ids: set[NodeID] = set(nodes.keys())
        stub_node_ids: set[NodeID] = set()
        for rel in edges:
            if rel.src not in known_node_ids:
                stub_node_ids.add(rel.src)
            if rel.dst not in known_node_ids:
                stub_node_ids.add(rel.dst)

        all_node_ids: list[NodeID] = sorted(
            list(known_node_ids | stub_node_ids), key=lambda nid: str(nid)
        )

        def edge_sort_key(rel: RelationshipBase) -> tuple[str, str, str, str]:
            payload = rel.model_dump(mode="json")
            rel_type = payload.get("type")
            if not isinstance(rel_type, str) or not rel_type:
                rel_type = rel.__class__.__name__
            payload_str = json.dumps(payload, ensure_ascii=False, sort_keys=True)
            return (str(rel.src), str(rel.dst), str(rel_type), payload_str)

        sorted_edges = sorted(edges, key=edge_sort_key)

        lines: list[str] = [f"digraph {_dot_quote(self.graph_name)} {{"]
        lines.extend(
            [
                "  graph [rankdir=LR];",
                '  node [shape=box, fontname="Courier", fontsize=10];',
                '  edge [fontname="Courier", fontsize=9];',
            ]
        )

        lines.append("  // nodes")
        for node_id in all_node_ids:
            node = nodes.get(node_id)
            if node is None:
                label = f"kind: MissingNode\nid: {node_id}"
            else:
                label = _node_label(node_id=node_id, node=node)
            lines.append(f"  {_dot_quote(str(node_id))} [label={_dot_quote(label)}];")

        lines.append("  // edges")
        for rel in sorted_edges:
            label = _edge_label(rel)
            lines.append(
                f"  {_dot_quote(str(rel.src))} -> {_dot_quote(str(rel.dst))} "
                f"[label={_dot_quote(label)}];"
            )

        lines.append("}")
        return "\n".join(lines) + "\n"

    def load(self, nodes: dict[NodeID, Node], edges: list[RelationshipBase]) -> None:
        """Write nodes and edges to the configured DOT file.

        Args:
            nodes: Mapping of node id to Node model.
            edges: List of relationship models connecting nodes.
        """

        if self.output_path.parent and not self.output_path.parent.exists():
            self.output_path.parent.mkdir(parents=True, exist_ok=True)

        dot_source = self._to_dot(nodes, edges)

        try:
            with self.output_path.open("w", encoding="utf-8") as f:
                f.write(dot_source)
        except OSError:
            logger.exception("Failed to write CPG DOT to %s", self.output_path)
            raise
