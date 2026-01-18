from models.base import NodeID
from models.edges.call_graph import CallGraphCalls
from models.edges.data_flow import DataFlowDefinedBy, DefinitionOperation
from models.nodes import (
    FunctionNode,
    VariableNode,
)
from models.nodes.code import ClassNode
from services.cpg_parser.ts_parser.cpg_builder import CPGFileBuilder
from tests.consts import TEST_CLASS_FILE, TEST_VARIABLES_FILE
from tests.utils import symbol_byte_index


def test_tree_sitter_parse__on_class__returns_correct_nodes_and_edges() -> None:
    parser = CPGFileBuilder(path=TEST_CLASS_FILE)

    nodes, _edges = parser.build()

    subtotal_method_id = NodeID.create(
        "function", "subtotal", str(TEST_CLASS_FILE), 202
    )
    product_class_id = NodeID.create("class", "Product", str(TEST_CLASS_FILE), 60)
    order_item_class_id = NodeID.create("class", "OrderItem", str(TEST_CLASS_FILE), 132)

    assert subtotal_method_id in nodes
    assert nodes[subtotal_method_id] == FunctionNode(
        identifier=subtotal_method_id,
        name="subtotal",
        file_path=TEST_CLASS_FILE,
        line_start=18,
        line_end=19,
        token_count=3,
    )

    assert product_class_id in nodes
    assert nodes[product_class_id] == ClassNode(
        identifier=product_class_id,
        name="Product",
        file_path=TEST_CLASS_FILE,
        line_start=5,
        line_end=5,
    )

    assert order_item_class_id in nodes
    assert nodes[order_item_class_id] == ClassNode(
        identifier=order_item_class_id,
        name="OrderItem",
        file_path=TEST_CLASS_FILE,
        line_start=12,
        line_end=14,
    )


def test_tree_sitter_parse__on_variables__returns_correct_nodes_and_edges() -> None:
    parser = CPGFileBuilder(path=TEST_VARIABLES_FILE)

    nodes, edges = parser.build()

    data = TEST_VARIABLES_FILE.read_bytes()

    def idx(needle: bytes, start: int = 0) -> int:
        return symbol_byte_index(data, needle, start)

    # --- NodeIDs (start_byte values are asserted to ensure stable IDs) ---
    a_def_sb = idx(b"a = 1")
    a_def_id = NodeID.create("variable", "a", str(TEST_VARIABLES_FILE), a_def_sb)

    b_def_sb = idx(b"b = 'asdeasd'")
    b_def_id = NodeID.create("variable", "b", str(TEST_VARIABLES_FILE), b_def_sb)

    c_def_sb = idx(b"c = b")
    c_def_id = NodeID.create("variable", "c", str(TEST_VARIABLES_FILE), c_def_sb)

    d_def_sb = idx(b"d = a + 5")
    d_def_id = NodeID.create("variable", "d", str(TEST_VARIABLES_FILE), d_def_sb)

    e_def_sb = idx(b"e = b + 'xyz'")
    e_def_id = NodeID.create("variable", "e", str(TEST_VARIABLES_FILE), e_def_sb)

    f_def_sb = idx(b"f = d + a")
    f_def_id = NodeID.create("variable", "f", str(TEST_VARIABLES_FILE), f_def_sb)

    h_def_sb = idx(b"h = b + e")
    h_def_id = NodeID.create("variable", "h", str(TEST_VARIABLES_FILE), h_def_sb)

    my_function_sb = idx(b"def my_function")
    my_function_id = NodeID.create(
        "function", "my_function", str(TEST_VARIABLES_FILE), my_function_sb
    )
    param1_sb = idx(b"param1", my_function_sb)
    param2_sb = idx(b"param2", my_function_sb)
    str_param_sb = idx(b"str", my_function_sb)
    param1_def_id = NodeID.create(
        "variable", "param1", str(TEST_VARIABLES_FILE), param1_sb
    )
    param2_def_id = NodeID.create(
        "variable", "param2", str(TEST_VARIABLES_FILE), param2_sb
    )
    # The current parser treats the type annotation identifier `str` as a parameter identifier.
    str_param_def_id = NodeID.create(
        "variable", "str", str(TEST_VARIABLES_FILE), str_param_sb
    )

    local_var_sb = idx(b"local_var =")
    local_var_def_id = NodeID.create(
        "variable", "local_var", str(TEST_VARIABLES_FILE), local_var_sb
    )

    s_def_sb = idx(b"s = my_function(e)")
    s_def_id = NodeID.create("variable", "s", str(TEST_VARIABLES_FILE), s_def_sb)
    s_call_sb = s_def_sb + len(b"s = ")
    s_src_call_id = NodeID.create(
        "call", "my_function(e)", str(TEST_VARIABLES_FILE), s_call_sb
    )

    digit_def_sb = idx(b"digit = my_function(str(d), '123')")
    digit_def_id = NodeID.create(
        "variable", "digit", str(TEST_VARIABLES_FILE), digit_def_sb
    )
    digit_call_sb = digit_def_sb + len(b"digit = ")
    digit_src_call_id = NodeID.create(
        "call", "my_function(str(d), '123')", str(TEST_VARIABLES_FILE), digit_call_sb
    )
    digit_src_call_str_d_id = NodeID.create(
        "call", "str(d)", str(TEST_VARIABLES_FILE), idx(b"str(d)", digit_def_sb)
    )

    # --- Variable/literal nodes ---
    assert a_def_id in nodes
    assert nodes[a_def_id] == VariableNode(
        identifier=a_def_id,
        name="a",
        type_hint="",
        line_start=1,
        line_end=1,
        file_path=TEST_VARIABLES_FILE,
    )

    assert b_def_id in nodes
    assert nodes[b_def_id] == VariableNode(
        identifier=b_def_id,
        name="b",
        type_hint="",
        line_start=2,
        line_end=2,
        file_path=TEST_VARIABLES_FILE,
    )

    assert c_def_id in nodes
    assert nodes[c_def_id] == VariableNode(
        identifier=c_def_id,
        name="c",
        type_hint="",
        line_start=3,
        line_end=3,
        file_path=TEST_VARIABLES_FILE,
    )
    # RHS references reuse the defining node ID (no duplicate node for `b` here)

    assert d_def_id in nodes
    assert nodes[d_def_id] == VariableNode(
        identifier=d_def_id,
        name="d",
        type_hint="",
        line_start=4,
        line_end=4,
        file_path=TEST_VARIABLES_FILE,
    )
    # RHS references reuse the defining node ID (no duplicate node for `a` here)

    assert f_def_id in nodes
    assert nodes[f_def_id] == VariableNode(
        identifier=f_def_id,
        name="f",
        type_hint="",
        line_start=6,
        line_end=6,
        file_path=TEST_VARIABLES_FILE,
    )
    # RHS references reuse the defining node IDs for `d` and `a`

    assert h_def_id in nodes
    assert nodes[h_def_id] == VariableNode(
        identifier=h_def_id,
        name="h",
        type_hint="",
        line_start=8,
        line_end=8,
        file_path=TEST_VARIABLES_FILE,
    )
    # RHS references reuse the defining node IDs for `b` and `e`

    # --- Variables inside function ---
    assert my_function_id in nodes
    assert nodes[my_function_id] == FunctionNode(
        identifier=my_function_id,
        name="my_function",
        file_path=TEST_VARIABLES_FILE,
        line_start=10,
        line_end=12,
        token_count=3,
    )

    assert param1_def_id in nodes
    assert nodes[param1_def_id] == VariableNode(
        identifier=param1_def_id,
        name="param1",
        type_hint="",
        line_start=10,
        line_end=10,
        file_path=TEST_VARIABLES_FILE,
    )
    assert param2_def_id in nodes
    assert nodes[param2_def_id] == VariableNode(
        identifier=param2_def_id,
        name="param2",
        type_hint="str",
        line_start=10,
        line_end=10,
        file_path=TEST_VARIABLES_FILE,
    )
    assert str_param_def_id in nodes
    assert nodes[str_param_def_id] == VariableNode(
        identifier=str_param_def_id,
        name="str",
        type_hint="",
        line_start=10,
        line_end=10,
        file_path=TEST_VARIABLES_FILE,
    )

    assert local_var_def_id in nodes
    assert nodes[local_var_def_id] == VariableNode(
        identifier=local_var_def_id,
        name="local_var",
        type_hint="",
        line_start=11,
        line_end=11,
        file_path=TEST_VARIABLES_FILE,
    )
    # RHS references reuse the defining parameter node IDs

    # --- Variables assigned from calls ---
    assert s_def_id in nodes
    assert nodes[s_def_id] == VariableNode(
        identifier=s_def_id,
        name="s",
        type_hint="",
        line_start=15,
        line_end=15,
        file_path=TEST_VARIABLES_FILE,
    )
    assert s_src_call_id in nodes

    assert digit_def_id in nodes
    assert nodes[digit_def_id] == VariableNode(
        identifier=digit_def_id,
        name="digit",
        type_hint="",
        line_start=16,
        line_end=16,
        file_path=TEST_VARIABLES_FILE,
    )
    assert digit_src_call_id in nodes
    assert digit_src_call_str_d_id in nodes

    # --- Data-flow edges (DEFINED_BY) ---
    # c is defined by b
    assert (
        DataFlowDefinedBy(
            src=b_def_id,
            dst=c_def_id,
            operation=DefinitionOperation.ASSIGNMENT,
        )
        in edges
    )

    # d is defined by a
    assert (
        DataFlowDefinedBy(
            src=a_def_id,
            dst=d_def_id,
            operation=DefinitionOperation.ASSIGNMENT,
        )
        in edges
    )

    # f is defined by d and a
    assert (
        DataFlowDefinedBy(
            src=d_def_id,
            dst=f_def_id,
            operation=DefinitionOperation.ASSIGNMENT,
        )
        in edges
    )
    assert (
        DataFlowDefinedBy(
            src=a_def_id,
            dst=f_def_id,
            operation=DefinitionOperation.ASSIGNMENT,
        )
        in edges
    )

    # h is defined by b and e
    assert (
        DataFlowDefinedBy(
            src=b_def_id,
            dst=h_def_id,
            operation=DefinitionOperation.ASSIGNMENT,
        )
        in edges
    )
    assert (
        DataFlowDefinedBy(
            src=e_def_id,
            dst=h_def_id,
            operation=DefinitionOperation.ASSIGNMENT,
        )
        in edges
    )

    # my_function parameters
    assert (
        DataFlowDefinedBy(
            src=my_function_id,
            dst=param1_def_id,
            operation=DefinitionOperation.PARAMETER,
        )
        in edges
    )
    assert (
        DataFlowDefinedBy(
            src=my_function_id,
            dst=param2_def_id,
            operation=DefinitionOperation.PARAMETER,
        )
        in edges
    )
    assert (
        DataFlowDefinedBy(
            src=my_function_id,
            dst=str_param_def_id,
            operation=DefinitionOperation.PARAMETER,
        )
        in edges
    )

    # local_var = param1 + param2
    assert (
        DataFlowDefinedBy(
            src=param1_def_id,
            dst=local_var_def_id,
            operation=DefinitionOperation.ASSIGNMENT,
        )
        in edges
    )
    assert (
        DataFlowDefinedBy(
            src=param2_def_id,
            dst=local_var_def_id,
            operation=DefinitionOperation.ASSIGNMENT,
        )
        in edges
    )

    # s = my_function(e)
    assert (
        DataFlowDefinedBy(
            src=e_def_id,
            dst=s_def_id,
            operation=DefinitionOperation.ASSIGNMENT,
        )
        in edges
    )

    assert (
        CallGraphCalls(
            src=s_src_call_id,
            dst=my_function_id,
            is_direct=True,
            call_depth=0,
        )
        in edges
    )
    assert (
        DataFlowDefinedBy(
            src=s_src_call_id,
            dst=s_def_id,
            operation=DefinitionOperation.ASSIGNMENT,
        )
        in edges
    )

    # digit = my_function(str(d), '123')
    assert (
        DataFlowDefinedBy(
            src=d_def_id,
            dst=digit_def_id,
            operation=DefinitionOperation.ASSIGNMENT,
        )
        in edges
    )
    assert (
        DataFlowDefinedBy(
            src=digit_src_call_id,
            dst=digit_def_id,
            operation=DefinitionOperation.ASSIGNMENT,
        )
        in edges
    )
    assert (
        DataFlowDefinedBy(
            src=digit_src_call_str_d_id,
            dst=digit_def_id,
            operation=DefinitionOperation.ASSIGNMENT,
        )
        in edges
    )

    assert (
        CallGraphCalls(
            src=digit_src_call_id,
            dst=my_function_id,
            is_direct=True,
            call_depth=0,
        )
        in edges
    )
