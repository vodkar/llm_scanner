from models.base import NodeID
from models.edges.data_flow import DataFlowDefinedBy, DataFlowUsedBy, DefinitionOperation
from models.nodes import (
    VariableNode,
)
from models.nodes.code import FunctionNode
from services.cpg_parser.ts_parser.cpg_builder import CPGFileBuilder
from tests.utils import symbol_byte_index

from .consts import TEST_GLOBAL_USAGE_FILE


def test_tree_sitter_parse__on_global_usage__returns_correct_global_usage() -> None:
    parser = CPGFileBuilder(path=TEST_GLOBAL_USAGE_FILE)

    nodes, edges = parser.build()

    data = TEST_GLOBAL_USAGE_FILE.read_bytes()

    def idx(needle: bytes, start: int = 0) -> int:
        return symbol_byte_index(data, needle, start)

    variable_nodes = list(filter(lambda n: isinstance(n, VariableNode), nodes.values()))
    # global_var, config, items (param), list (type-hint param), local_a, local_b,
    # x (param), int (type-hint param), y (param), int (type-hint param), result
    assert len(variable_nodes) == 11

    # --- module-level variable definitions ---

    global_var_sb = idx(b"global_var =")
    global_var_id = NodeID.create(
        "variable", "global_var", str(TEST_GLOBAL_USAGE_FILE), global_var_sb
    )
    assert global_var_id in nodes
    assert nodes[global_var_id] == VariableNode(
        identifier=global_var_id,
        name="global_var",
        file_path=TEST_GLOBAL_USAGE_FILE,
        line_start=1,
        line_end=1,
    )

    config_sb = idx(b"config =")
    config_id = NodeID.create("variable", "config", str(TEST_GLOBAL_USAGE_FILE), config_sb)
    assert config_id in nodes
    assert nodes[config_id] == VariableNode(
        identifier=config_id,
        name="config",
        file_path=TEST_GLOBAL_USAGE_FILE,
        line_start=2,
        line_end=2,
    )

    # --- function definitions ---

    main_func_sb = idx(b"def main()")
    main_func_id = NodeID.create("function", "main", str(TEST_GLOBAL_USAGE_FILE), main_func_sb)
    assert main_func_id in nodes
    assert nodes[main_func_id] == FunctionNode(
        identifier=main_func_id,
        name="main",
        file_path=TEST_GLOBAL_USAGE_FILE,
        line_start=10,
        line_end=13,
    )

    # --- USED_BY: global_var referenced inside main via ``local_a = global_var`` ---

    used_by_global_var = DataFlowUsedBy(src=global_var_id, dst=main_func_id)
    assert used_by_global_var in edges

    # --- USED_BY: config referenced inside main via ``local_b = config["debug"]`` ---

    used_by_config = DataFlowUsedBy(src=config_id, dst=main_func_id)
    assert used_by_config in edges

    # --- local assignment definitions ---

    local_a_sb = idx(b"local_a =")
    local_a_id = NodeID.create("variable", "local_a", str(TEST_GLOBAL_USAGE_FILE), local_a_sb)
    assert local_a_id in nodes

    local_b_sb = idx(b"local_b =")
    local_b_id = NodeID.create("variable", "local_b", str(TEST_GLOBAL_USAGE_FILE), local_b_sb)
    assert local_b_id in nodes

    # --- DEFINED_BY edges for assignments ---

    assert (
        DataFlowDefinedBy(
            src=global_var_id,
            dst=local_a_id,
            operation=DefinitionOperation.ASSIGNMENT,
        )
        in edges
    )
    assert (
        DataFlowDefinedBy(
            src=config_id,
            dst=local_b_id,
            operation=DefinitionOperation.ASSIGNMENT,
        )
        in edges
    )


def test_tree_sitter_parse__on_global_usage__no_duplicate_used_by() -> None:
    """Verify that multiple references to the same outer variable produce only one USED_BY edge."""
    parser = CPGFileBuilder(path=TEST_GLOBAL_USAGE_FILE)

    _, edges = parser.build()

    used_by_edges = [e for e in edges if isinstance(e, DataFlowUsedBy)]
    src_dst_pairs = [(e.src, e.dst) for e in used_by_edges]

    # Each (src, dst) pair should appear at most once.
    assert len(src_dst_pairs) == len(set(src_dst_pairs))
