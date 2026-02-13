from __future__ import annotations

from typing import Final, LiteralString

NODE_QUERY_BY_LABEL: Final[dict[str, LiteralString]] = {
    "Code": (
        "UNWIND $rows AS r "
        "MERGE (n:Code {id: r.id}) "
        "SET n.node_kind = r.node_kind, "
        "    n += r.attrs"
    ),
    "Function": (
        "UNWIND $rows AS r "
        "MERGE (n:Code:Function {id: r.id}) "
        "SET n.node_kind = r.node_kind, "
        "    n += r.attrs"
    ),
    "Class": (
        "UNWIND $rows AS r "
        "MERGE (n:Code:Class {id: r.id}) "
        "SET n.node_kind = r.node_kind, "
        "    n += r.attrs"
    ),
    "CodeBlock": (
        "UNWIND $rows AS r "
        "MERGE (n:Code:CodeBlock {id: r.id}) "
        "SET n.node_kind = r.node_kind, "
        "    n += r.attrs"
    ),
    "Module": (
        "UNWIND $rows AS r "
        "MERGE (n:Code:Module {id: r.id}) "
        "SET n.node_kind = r.node_kind, "
        "    n += r.attrs"
    ),
    "Variable": (
        "UNWIND $rows AS r "
        "MERGE (n:Code:Variable {id: r.id}) "
        "SET n.node_kind = r.node_kind, "
        "    n += r.attrs"
    ),
    "Call": (
        "UNWIND $rows AS r "
        "MERGE (n:Code:Call {id: r.id}) "
        "SET n.node_kind = r.node_kind, "
        "    n += r.attrs"
    ),
}

FINDING_NODE_QUERIES: Final[dict[str, LiteralString]] = {
    "BanditFinding": (
        "UNWIND $rows AS r "
        "MERGE (n:Finding:BanditFinding {id: r.id}) "
        "SET n.file = r.file, "
        "    n.line_number = r.line_number, "
        "    n.cwe_id = r.cwe_id, "
        "    n.severity = r.severity"
    ),
    "DlintFinding": (
        "UNWIND $rows AS r "
        "MERGE (n:Finding:DlintFinding {id: r.id}) "
        "SET n.file = r.file, "
        "    n.line_number = r.line_number, "
        "    n.issue_id = r.issue_id"
    ),
}

FINDING_RELATIONSHIP_QUERIES: Final[dict[str, LiteralString]] = {
    "REPORTS": (
        "UNWIND $rows AS r "
        "MATCH (s:Finding {id:r.src}), (d:Code {id:r.dst}) "
        "MERGE (s)-[e:REPORTS]->(d)"
    ),
}

FINDINGS_BY_PROJECT_QUERY_BY_LABEL: Final[dict[str, LiteralString]] = {
    "BanditFinding": (
        "MATCH (f:Finding:BanditFinding) "
        "WHERE f.file STARTS WITH $root OR f.file STARTS WITH $root_alt "
        "RETURN f.id AS id, f.file AS file, f.line_number AS line_number, "
        "f.cwe_id AS cwe_id, f.severity AS severity "
        "ORDER BY f.file, f.line_number"
    ),
    "DlintFinding": (
        "MATCH (f:Finding:DlintFinding) "
        "WHERE f.file STARTS WITH $root OR f.file STARTS WITH $root_alt "
        "RETURN f.id AS id, f.file AS file, f.line_number AS line_number, "
        "f.issue_id AS issue_id "
        "ORDER BY f.file, f.line_number"
    ),
}

FINDINGS_BY_LABEL_QUERY_BY_LABEL: Final[dict[str, LiteralString]] = {
    "BanditFinding": (
        "MATCH (f:Finding:BanditFinding) "
        "RETURN f.id AS id, f.file AS file, f.line_number AS line_number, "
        "f.cwe_id AS cwe_id, f.severity AS severity "
        "ORDER BY f.file, f.line_number"
    ),
    "DlintFinding": (
        "MATCH (f:Finding:DlintFinding) "
        "RETURN f.id AS id, f.file AS file, f.line_number AS line_number, "
        "f.issue_id AS issue_id "
        "ORDER BY f.file, f.line_number"
    ),
}

RELATIONSHIP_QUERY_BY_TYPE: Final[dict[str, LiteralString]] = {
    "CALLS": (
        "UNWIND $rows AS r "
        "MATCH (s:Code {id:r.src}), (d:Code {id:r.dst}) "
        "MERGE (s)-[e:CALLS]->(d) "
        "SET e += r.attrs"
    ),
    "CALLED_BY": (
        "UNWIND $rows AS r "
        "MATCH (s:Code {id:r.src}), (d:Code {id:r.dst}) "
        "MERGE (s)-[e:CALLED_BY]->(d) "
        "SET e += r.attrs"
    ),
    "CONTAINS": (
        "UNWIND $rows AS r "
        "MATCH (s:Code {id:r.src}), (d:Code {id:r.dst}) "
        "MERGE (s)-[e:CONTAINS]->(d) "
        "SET e += r.attrs"
    ),
    "NEXT": (
        "UNWIND $rows AS r "
        "MATCH (s:Code {id:r.src}), (d:Code {id:r.dst}) "
        "MERGE (s)-[e:NEXT]->(d) "
        "SET e += r.attrs"
    ),
    "DEFINED_BY": (
        "UNWIND $rows AS r "
        "MATCH (s:Code {id:r.src}), (d:Code {id:r.dst}) "
        "MERGE (s)-[e:DEFINED_BY]->(d) "
        "SET e += r.attrs"
    ),
    "FLOWS_TO": (
        "UNWIND $rows AS r "
        "MATCH (s:Code {id:r.src}), (d:Code {id:r.dst}) "
        "MERGE (s)-[e:FLOWS_TO]->(d) "
        "SET e += r.attrs"
    ),
    "SANITIZED_BY": (
        "UNWIND $rows AS r "
        "MATCH (s:Code {id:r.src}), (d:Code {id:r.dst}) "
        "MERGE (s)-[e:SANITIZED_BY]->(d) "
        "SET e += r.attrs"
    ),
    "REPORTS": (
        "UNWIND $rows AS r "
        "MATCH (s:Code {id:r.src}), (d:Code {id:r.dst}) "
        "MERGE (s)-[e:REPORTS]->(d) "
        "SET e += r.attrs"
    ),
    "SUGGESTS_VULNERABILITY": (
        "UNWIND $rows AS r "
        "MATCH (s:Code {id:r.src}), (d:Code {id:r.dst}) "
        "MERGE (s)-[e:SUGGESTS_VULNERABILITY]->(d) "
        "SET e += r.attrs"
    ),
    "CONFLICTS_WITH": (
        "UNWIND $rows AS r "
        "MATCH (s:Code {id:r.src}), (d:Code {id:r.dst}) "
        "MERGE (s)-[e:CONFLICTS_WITH]->(d) "
        "SET e += r.attrs"
    ),
    "USED_IN": (
        "UNWIND $rows AS r "
        "MATCH (s:Code {id:r.src}), (d:Code {id:r.dst}) "
        "MERGE (s)-[e:USED_IN {type:r.type}]->(d) "
        "SET e += r.attrs"
    ),
}


def is_supported_relationship_type(rel_type: str) -> bool:
    """Check whether a relationship type has a dedicated query.

    Args:
        rel_type: Relationship type identifier.

    Returns:
        True when the relationship type has an explicit query.
    """

    return rel_type in RELATIONSHIP_QUERY_BY_TYPE


def finding_node_query(finding_type: str) -> LiteralString:
    """Return a literal query for a finding node type.

    Args:
        finding_type: Type of finding node (e.g., 'BanditFinding', 'DlintFinding').

    Returns:
        Literal query for the requested finding type.
    """

    return FINDING_NODE_QUERIES[finding_type]


def finding_relationship_query(rel_type: str) -> LiteralString:
    """Return a literal query for a finding relationship type.

    Args:
        rel_type: Relationship type identifier.

    Returns:
        Literal query for the requested relationship.
    """

    return FINDING_RELATIONSHIP_QUERIES.get(rel_type, FINDING_RELATIONSHIP_QUERIES["REPORTS"])


def findings_by_project_query(finding_label: str) -> LiteralString:
    """Return a literal query for project-scoped findings by label.

    Args:
        finding_label: Finding label to scope the query.

    Returns:
        Literal query used to fetch findings under a project root.
    """

    return FINDINGS_BY_PROJECT_QUERY_BY_LABEL[finding_label]


def findings_by_label_query(finding_label: str) -> LiteralString:
    """Return a literal query for findings by label.

    Args:
        finding_label: Finding label to scope the query.

    Returns:
        Literal query used to fetch findings for a label.
    """

    return FINDINGS_BY_LABEL_QUERY_BY_LABEL[finding_label]
