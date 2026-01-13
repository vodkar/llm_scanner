import unittest
from models.base import NodeID
from models.nodes import (
    CodeBlockNode,
    CodeBlockType,
    FunctionNode,
    ModuleNode,
    VariableNode,
    VariableScope,
)
from models.nodes.code import ClassNode
from services.cpg_parser.cpg_builder import CPGFileBuilder
from services.cpg_parser.tree_sitter_cpg_parser import TreeSitterCPGParser
from tests.consts import TEST_CLASS_FILE, TEST_IMPORTS_FILE


def test_tree_sitter_parse__on_class__returns_correct_nodes_and_edges() -> None:
    parser = CPGFileBuilder(path=TEST_CLASS_FILE)

    nodes, edges = parser.build()

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
