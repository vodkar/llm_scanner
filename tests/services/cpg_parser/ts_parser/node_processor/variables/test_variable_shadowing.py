from models.base import NodeID
from models.edges.data_flow import DataFlowDefinedBy, DataFlowUsedBy, DefinitionOperation
from services.cpg_parser.ts_parser.cpg_builder import CPGFileBuilder
from tests.utils import symbol_byte_index

from .consts import TEST_SHADOWING_FILE


def test_tree_sitter_parse__shadowing__no_used_by_for_shadowed_variable() -> None:
    """When a local variable shadows a global, ``y = x`` should resolve to the
    local ``x`` — no USED_BY edge for the global ``x`` should be emitted."""
    parser = CPGFileBuilder(path=TEST_SHADOWING_FILE)

    nodes, edges = parser.build()

    data = TEST_SHADOWING_FILE.read_bytes()

    def idx(needle: bytes, start: int = 0) -> int:
        return symbol_byte_index(data, needle, start)

    # Global x = 1  (line 1)
    global_x_sb = idx(b"x = 1")
    global_x_id = NodeID.create("variable", "x", str(TEST_SHADOWING_FILE), global_x_sb)
    assert global_x_id in nodes

    # The global ``x`` must NOT appear in any USED_BY edge (it is shadowed by ``x = 2``).
    used_by_edges = [e for e in edges if isinstance(e, DataFlowUsedBy)]
    for edge in used_by_edges:
        assert edge.src != global_x_id, (
            f"Global x should not be USED_BY anything because it is shadowed, but found {edge}"
        )


def test_tree_sitter_parse__shadowing__local_defined_by_local() -> None:
    """``y = x`` inside foo should produce DEFINED_BY from the local ``x`` (not global)."""
    parser = CPGFileBuilder(path=TEST_SHADOWING_FILE)

    nodes, edges = parser.build()

    data = TEST_SHADOWING_FILE.read_bytes()

    def idx(needle: bytes, start: int = 0) -> int:
        return symbol_byte_index(data, needle, start)

    # Local x = 2  inside foo (line 5)
    local_x_sb = idx(b"x = 2")
    local_x_id = NodeID.create("variable", "x", str(TEST_SHADOWING_FILE), local_x_sb)
    assert local_x_id in nodes

    # y = x  inside foo (line 6)
    y_sb = idx(b"y = x")
    y_id = NodeID.create("variable", "y", str(TEST_SHADOWING_FILE), y_sb)
    assert y_id in nodes

    assert (
        DataFlowDefinedBy(
            src=local_x_id,
            dst=y_id,
            operation=DefinitionOperation.ASSIGNMENT,
        )
        in edges
    )
