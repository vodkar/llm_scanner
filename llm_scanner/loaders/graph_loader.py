from __future__ import annotations


from clients.neo4j import Neo4jClient
from services.cpg_parser import Node
from models.edge import Edge


class GraphLoader:
    def __init__(self, client: Neo4jClient) -> None:
        self.client = client
        self._ensure_indexes()

    def _ensure_indexes(self) -> None:
        # Basic indexes to speed up merges
        self.client.run_write("CREATE INDEX IF NOT EXISTS FOR (n:Code) ON (n.id)")

    def load(self, nodes: dict[str, Node], edges: list[Edge]) -> None:
        # MERGE nodes
        query_nodes = (
            "UNWIND $rows AS r "
            "MERGE (n:Code {id: r.id}) "
            "SET n += {type:r.type, name:r.name, qualname:r.qualname, file:r.file, "
            "lineno:r.lineno, end_lineno:r.end_lineno, code:r.code, "
            "imports:r.imports, globals:r.globals, locals:r.locals}"
        )
        node_rows = [n.model_dump() for n in nodes.values()]
        self.client.run_write(query_nodes, {"rows": node_rows})

        # MERGE edges
        query_edges = (
            "UNWIND $rows AS r "
            "MATCH (s:Code {id:r.src}), (d:Code {id:r.dst}) "
            "MERGE (s)-[e:REL {type:r.type}]->(d)"
        )
        edge_rows: list[dict[str, str]] = [
            {"src": e.src, "dst": e.dst, "type": e.type} for e in edges
        ]
        if edge_rows:
            self.client.run_write(query_edges, {"rows": edge_rows})
