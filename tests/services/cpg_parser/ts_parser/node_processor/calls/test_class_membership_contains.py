from collections import defaultdict, deque

from models.base import NodeID
from models.edges.control_flow import ControlFlowContains
from models.edges.data_flow import DataFlowDefinedBy, DefinitionOperation
from repositories.queries import code_traversal_relationship_types
from services.cpg_parser.ts_parser.cpg_builder import CPGFileBuilder
from tests.utils import symbol_byte_index

from .consts import TEST_CLASS_MEMBERSHIP_FILE


def _ids() -> dict[str, NodeID]:
    data = TEST_CLASS_MEMBERSHIP_FILE.read_bytes()
    path = str(TEST_CLASS_MEMBERSHIP_FILE)

    def idx(needle: bytes, start: int = 0) -> int:
        return symbol_byte_index(data, needle, start)

    return {
        "class": NodeID.create("class", "Service", path, idx(b"class Service")),
        "helper": NodeID.create("function", "helper", path, idx(b"def helper")),
        "vuln": NodeID.create("function", "vuln", path, idx(b"def vuln")),
        "s1": NodeID.create("function", "s1", path, idx(b"def s1")),
        "s2": NodeID.create("function", "s2", path, idx(b"def s2")),
    }


def test_class_membership_emits_contains_not_defined_by() -> None:
    """Class -> member structural edges must be CONTAINS, never DEFINED_BY."""
    _nodes, edges = CPGFileBuilder(path=TEST_CLASS_MEMBERSHIP_FILE).build()
    ids = _ids()

    for member in ("helper", "vuln", "s1", "s2"):
        assert ControlFlowContains(src=ids["class"], dst=ids[member]) in edges
        assert (
            DataFlowDefinedBy(
                src=ids["class"],
                dst=ids[member],
                operation=DefinitionOperation.ASSIGNMENT,
            )
            not in edges
        )


def test_real_dataflow_defined_by_still_emitted() -> None:
    """Re-typing class membership must not disturb true data-flow DEFINED_BY."""
    data = TEST_CLASS_MEMBERSHIP_FILE.read_bytes()
    path = str(TEST_CLASS_MEMBERSHIP_FILE)

    def idx(needle: bytes, start: int = 0) -> int:
        return symbol_byte_index(data, needle, start)

    _nodes, edges = CPGFileBuilder(path=TEST_CLASS_MEMBERSHIP_FILE).build()

    raw_id = NodeID.create("variable", "raw", path, idx(b"raw)"))
    cleaned_id = NodeID.create("variable", "cleaned", path, idx(b"cleaned ="))
    assert (
        DataFlowDefinedBy(src=raw_id, dst=cleaned_id, operation=DefinitionOperation.ASSIGNMENT)
        in edges
    )


def test_neighborhood_traversal_no_longer_floods_through_class_hub() -> None:
    """BFS over the neighborhood-traversal edge set must follow the call chain
    (vuln -> helper) but must NOT pull in uncalled siblings s1/s2 via the
    class-membership hub."""
    _nodes, edges = CPGFileBuilder(path=TEST_CLASS_MEMBERSHIP_FILE).build()
    ids = _ids()

    traversal_types = set(code_traversal_relationship_types())
    adjacency: dict[NodeID, set[NodeID]] = defaultdict(set)
    for edge in edges:
        if str(getattr(edge, "type", "")) not in traversal_types:
            continue
        adjacency[edge.src].add(edge.dst)
        adjacency[edge.dst].add(edge.src)

    seen: set[NodeID] = {ids["vuln"]}
    queue: deque[tuple[NodeID, int]] = deque([(ids["vuln"], 0)])
    while queue:
        node, depth = queue.popleft()
        if depth >= 3:
            continue
        for neighbor in adjacency.get(node, ()):
            if neighbor not in seen:
                seen.add(neighbor)
                queue.append((neighbor, depth + 1))

    assert ids["helper"] in seen, "called helper must remain reachable via call chain"
    assert ids["s1"] not in seen, "uncalled sibling s1 must not be pulled in via class hub"
    assert ids["s2"] not in seen, "uncalled sibling s2 must not be pulled in via class hub"
