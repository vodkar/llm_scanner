from __future__ import annotations

from clients.neo4j import Neo4jClient
from loaders.bandit_report import BanditReport
from loaders.dlint_report import DlintReport
from models.edges import Edge
from models.nodes import Node


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
            "MERGE (s)-[e:USED_IN {type:r.type}]->(d)"
        )
        edge_rows: list[dict[str, str]] = [
            {"src": e.src, "dst": e.dst, "type": e.type} for e in edges
        ]
        if edge_rows:
            self.client.run_write(query_edges, {"rows": edge_rows})

    def load_bandit_report(self, report: BanditReport) -> None:
        query = (
            "UNWIND $rows AS r "
            "MERGE (i:Issue {id: r.id}) "
            "SET i += {cwe: r.cwe, severity: r.severity, description: r.description, "
            "line_number: r.line_number, column_number: r.column_number, "
            "line_range: r.line_range}"
        )
        issue_rows: list[dict[str, int | str | list[int]]] = []
        for issue in report.issues:
            # Deterministic ID for Bandit issues
            issue_id: str = (
                f"BANDIT::{issue.severity}:{issue.cwe}:{issue.file}:"
                f"{issue.line_number}:{issue.column_number}"
            )
            issue_rows.append(
                {
                    "id": issue_id,
                    "cwe": issue.cwe,
                    "severity": str(issue.severity),
                    "description": issue.description,
                    "line_number": issue.line_number,
                    "column_number": issue.column_number,
                    "line_range": issue.line_range,
                }
            )
        self.client.run_write(query, {"rows": issue_rows})

    def load_dlint_report(self, report: DlintReport) -> None:
        query = (
            "UNWIND $rows AS r "
            "MERGE (i:Issue {id: r.id}) "
            "SET i += {code: r.code, description: r.description, "
            "line_number: r.line_number, column_number: r.column_number}"
        )
        issue_rows: list[dict[str, int | str]] = []
        for issue in report.issues:
            issue_id: str = (
                f"DLINT::{issue.code}:{issue.file}:{issue.line_number}:{issue.column_number}"
            )
            issue_rows.append(
                {
                    "id": issue_id,
                    "code": issue.code,
                    "description": issue.description,
                    "line_number": issue.line_number,
                    "column_number": issue.column_number,
                }
            )
        if issue_rows:
            self.client.run_write(query, {"rows": issue_rows})
