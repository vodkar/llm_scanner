from typing import Final, LiteralString, cast

from models.edges.call_graph import CallGraphRelationshipType
from models.edges.control_flow import ControlFlowRelationshipType
from models.edges.data_flow import DataFlowRelationshipType

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


CODE_TRAVERSAL_RELATIONSHIP_TYPES: Final[tuple[str, ...]] = (
    *tuple(DataFlowRelationshipType),
    *tuple(CallGraphRelationshipType),
    *tuple(ControlFlowRelationshipType),
)

CODE_NODES_BY_FILE_LINE_QUERY: Final[LiteralString] = (
    "UNWIND $rows AS r "
    "MATCH (c:Code) "
    "WHERE c.file_path = r.file_path "
    "AND r.line_number >= c.line_start "
    "AND r.line_number <= c.line_end "
    "RETURN r.file_path AS file_path, r.line_number AS line_number, "
    "c.id AS id, c.file_path AS node_file_path, c.line_start AS line_start, "
    "c.line_end AS line_end, c.node_kind AS node_kind, "
    "c.finding_evidence_score AS finding_evidence_score, "
    "c.security_path_score AS security_path_score"
)

CODE_NODES_BY_FILE_SPAN_QUERY: Final[LiteralString] = (
    "UNWIND $rows AS r "
    "MATCH (c:Code) "
    "WHERE c.file_path = r.file_path "
    "AND c.line_start <= r.end_line "
    "AND c.line_end >= r.start_line "
    "RETURN r.file_path AS file_path, r.start_line AS start_line, r.end_line AS end_line, "
    "c.id AS id, c.file_path AS node_file_path, c.line_start AS line_start, "
    "c.line_end AS line_end, c.node_kind AS node_kind, "
    "c.finding_evidence_score AS finding_evidence_score, "
    "c.security_path_score AS security_path_score"
)


def _relationship_query(rel_type: str) -> LiteralString:
    """Build a literal query for a relationship type.

    Args:
        rel_type: Relationship type identifier.

    Returns:
        Literal query for the requested relationship.
    """

    query = (
        "UNWIND $rows AS r "
        "MATCH (s:Code {id:r.src}), (d:Code {id:r.dst}) "
        f"MERGE (s)-[e:{rel_type}]->(d) "
        "SET e += r.attrs"
    )
    return cast(LiteralString, query)


RELATIONSHIP_QUERY_BY_TYPE: Final[dict[str, LiteralString]] = {
    rel_type: _relationship_query(rel_type) for rel_type in CODE_TRAVERSAL_RELATIONSHIP_TYPES
}


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


def _validated_depth(max_depth: int) -> int:
    """Validate traversal depth for BFS queries.

    Args:
        max_depth: Requested maximum traversal depth.

    Returns:
        Non-negative integer traversal depth.

    Raises:
        ValueError: If max_depth is negative.
    """

    if max_depth < 0:
        raise ValueError("max_depth must be non-negative")
    return int(max_depth)


def _relationship_union_pattern(relationship_types: tuple[str, ...] | None = None) -> str:
    """Build Cypher relationship union pattern for traversal."""

    rel_types = relationship_types or CODE_TRAVERSAL_RELATIONSHIP_TYPES
    return "|".join(rel_types)


def code_bfs_nodes_query(
    max_depth: int,
    relationship_types: tuple[str, ...] | None = None,
) -> LiteralString:
    """Return a bounded literal query for BFS traversal over code nodes.

    Args:
        max_depth: Maximum traversal depth.

    Returns:
        Literal query used to fetch code nodes within a depth limit.
    """

    depth = _validated_depth(max_depth)
    rel_union = _relationship_union_pattern(relationship_types)

    if depth == 0 or not rel_union:
        query = (
            "MATCH (start:Code {id: $start_id}) "
            "RETURN start.id AS id, start.file_path AS file_path, "
            "start.line_start AS line_start, start.line_end AS line_end, "
            "start.name AS name, start.node_kind AS node_kind, 0 AS depth, "
            "start.finding_evidence_score AS finding_evidence_score, "
            "start.security_path_score AS security_path_score "
            # "ORDER BY file_path, line_start"
        )
        return cast(LiteralString, query)

    query = (
        "MATCH p=(start:Code {id: $start_id})"
        f"-[:{rel_union}*0..{depth}]-(n:Code) "
        "WITH n, min(length(p)) AS depth "
        "RETURN n.id AS id, n.file_path AS file_path, n.line_start AS line_start, "
        "n.line_end AS line_end, n.name AS name, n.node_kind AS node_kind, "
        "depth, n.finding_evidence_score AS finding_evidence_score, "
        "n.security_path_score AS security_path_score "
        # "ORDER BY depth, n.file_path, n.line_start"
    )
    return cast(LiteralString, query)


def code_bfs_nodes_batch_query(
    max_depth: int,
    relationship_types: tuple[str, ...] | None = None,
) -> LiteralString:
    """Return a bounded literal query for BFS traversal from multiple start nodes.

    Args:
        max_depth: Maximum traversal depth.

    Returns:
        Literal query used to fetch code nodes within a depth limit for many starts.
    """

    depth = _validated_depth(max_depth)
    rel_union = _relationship_union_pattern(relationship_types)

    if depth == 0 or not rel_union:
        query = (
            "UNWIND $start_ids AS sid "
            "MATCH (start:Code {id: sid}) "
            "RETURN sid AS start_id, start.id AS id, start.file_path AS file_path, "
            "start.line_start AS line_start, start.line_end AS line_end, "
            "start.name AS name, start.node_kind AS node_kind, 0 AS depth, "
            "start.finding_evidence_score AS finding_evidence_score, "
            "start.security_path_score AS security_path_score "
        )
        return cast(LiteralString, query)

    query = (
        "UNWIND $start_ids AS sid "
        "MATCH p=(start:Code {id: sid})"
        f"-[:{rel_union}*0..{depth}]-(n:Code) "
        "WITH sid, n, min(length(p)) AS depth "
        "RETURN sid AS start_id, n.id AS id, n.file_path AS file_path, "
        "n.line_start AS line_start, n.line_end AS line_end, "
        "n.name AS name, n.node_kind AS node_kind, depth, "
        "n.finding_evidence_score AS finding_evidence_score, "
        "n.security_path_score AS security_path_score "
    )
    return cast(LiteralString, query)


def code_nodes_by_file_span_query() -> LiteralString:
    """Return a literal query for code nodes overlapping file spans."""

    return CODE_NODES_BY_FILE_SPAN_QUERY


TAINT_HOP_DECAY: Final[dict[int, float]] = {1: 1.0, 2: 0.70, 3: 0.50, 4: 0.35}
TAINT_HOP_DECAY_DEFAULT: Final[float] = 0.20
_BACKWARD_DATAFLOW_REL_TYPES: Final[str] = "FLOWS_TO|DEFINED_BY"


def backward_dataflow_taint_query(max_taint_depth: int) -> LiteralString:
    """Return a Cypher query for backward DataFlow traversal from root nodes.

    Traverses FLOWS_TO and DEFINED_BY edges in reverse to find variables that
    participate in the data flow reaching the root vulnerability nodes.
    Returns each reachable node ID and its minimum hop distance from any root.
    """
    depth = _validated_depth(max_taint_depth)
    if depth == 0:
        return cast(LiteralString, "UNWIND $root_ids AS rid RETURN null AS id, 0 AS taint_hop")
    query = (
        "UNWIND $root_ids AS rid "
        "MATCH p=(root:Code {id: rid})"
        f"<-[:{_BACKWARD_DATAFLOW_REL_TYPES}*1..{depth}]-(n:Code) "
        "WITH n, min(length(p)) AS taint_hop "
        "RETURN n.id AS id, taint_hop"
    )
    return cast(LiteralString, query)


def taint_score_from_hop(taint_hop: int) -> float:
    """Map a DataFlow hop distance to a taint score."""
    return TAINT_HOP_DECAY.get(taint_hop, TAINT_HOP_DECAY_DEFAULT)


def code_traversal_relationship_types() -> tuple[str, ...]:
    """Return default relationship types used for code neighborhood traversal."""

    return CODE_TRAVERSAL_RELATIONSHIP_TYPES


def code_nodes_by_file_line_query() -> LiteralString:
    """Return a literal query for code nodes by file and line.

    Returns:
        Literal query used to find code nodes containing a line.
    """

    return CODE_NODES_BY_FILE_LINE_QUERY
