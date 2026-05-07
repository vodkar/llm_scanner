"""Shared constants for Neo4j repository integration tests."""

from typing import Final, LiteralString

BANDIT_FINDING_QUERY: Final[LiteralString] = (
    "MATCH (n:Finding:BanditFinding {id:$id}) "
    "RETURN n.file AS file, n.cwe_id AS cwe_id, n.severity AS severity"
)
DLINT_FINDING_QUERY: Final[LiteralString] = (
    "MATCH (n:Finding:DlintFinding {id:$id}) "
    "RETURN n.file AS file, n.line_number AS line_number, n.issue_id AS issue_id"
)
GRAPH_NODE_QUERY: Final[LiteralString] = (
    "MATCH (n:Code:Function {id:$id}) RETURN n.id AS id, n.name AS name"
)
GRAPH_EDGE_QUERY: Final[LiteralString] = (
    "MATCH (s:Code {id:$src})-[r:CALLS]->(d:Code {id:$dst}) "
    "RETURN r.type AS rel_type, r.is_direct AS is_direct, r.call_depth AS call_depth"
)
REPORTS_EDGE_QUERY: Final[LiteralString] = (
    "MATCH (f:Finding {id:$finding_id})-[r:REPORTS]->(c:Code {id:$code_id}) "
    "RETURN count(r) AS rel_count"
)
