from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, List, TypedDict

from loaders._serialization import flatten_node_rows
from models.edges import Edge
from models.nodes import Node

logger = logging.getLogger(__name__)


class JsonLoader:
    """Persist a Code Property Graph as JSON.

    The output JSON schema is a single object with two keys:
    - "nodes": list of node dictionaries
    - "edges": list of edge dictionaries

    Example:
    {
      "nodes": [{"id": "...", "type": "Function", ...}],
      "edges": [{"src": "...", "dst": "...", "type": "CALLS"}]
    }
    """

    def __init__(self, output_path: str | Path, indent: int = 2) -> None:
        """Create a JSON loader.

        Args:
            output_path: Target file path to write the JSON graph into.
            indent: Indentation level for pretty-printing JSON.
        """
        self.output_path: Path = Path(output_path)
        self.indent: int = indent

    def load(self, nodes: Dict[str, Node], edges: List[Edge]) -> None:
        """Write nodes and edges to the configured JSON file.

        Args:
            nodes: Mapping of node id to Node model.
            edges: List of Edge models connecting nodes.
        """
        # Ensure the parent directory exists
        if self.output_path.parent and not self.output_path.parent.exists():
            self.output_path.parent.mkdir(parents=True, exist_ok=True)

        # Prepare serializable rows. Pydantic's model_dump() handles sets via field_serializer.
        node_rows = flatten_node_rows(nodes)

        class EdgeRow(TypedDict):
            src: str
            dst: str
            type: str

        edge_rows: list[EdgeRow] = [
            {"src": e.src, "dst": e.dst, "type": str(e.type)} for e in edges
        ]

        class GraphJSON(TypedDict):
            nodes: list[dict[str, object]]
            edges: list[EdgeRow]

        payload: GraphJSON = {"nodes": node_rows, "edges": edge_rows}

        try:
            with self.output_path.open("w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=self.indent)
        except OSError:
            logger.exception("Failed to write CPG JSON to %s", self.output_path)
            raise
