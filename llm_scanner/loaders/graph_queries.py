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
