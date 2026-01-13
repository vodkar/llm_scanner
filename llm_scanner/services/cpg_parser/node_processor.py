from collections.abc import Iterator
from enum import StrEnum
from pathlib import Path
from pydantic import BaseModel, Field, PrivateAttr

from tree_sitter import Node as TSNode

from models.base import NodeID
from models.edges.base import RelationshipBase
from models.edges.core import Edge, EdgeType
from models.edges.data_flow import (
    DataFlowDefinedBy,
    DataFlowRelationshipType,
    DefinitionOperation,
)
from models.nodes import Node
from models.nodes.base import NodeType
from models.nodes.code import ClassNode, CodeBlockType, FunctionNode
from models.nodes.module_node import ModuleNode
from services.cpg_parser.consts import CODE_BLOCK_TYPES
from services.cpg_parser.types import ParserResult


class ProcessableNodeTypes(StrEnum):
    FUNCTION_DEFINITION = "function_definition"
    CLASS_DEFINITION = "class_definition"
    IMPORT_STATEMENT = "import_statement"
    IMPORT_FROM_STATEMENT = "import_from_statement"
    CALL = "call"
    BLOCK = "block"
    ASSIGNMENT = "assignment"
    EXPRESSION_STATEMENT = "expression_statement"


class NodeProcessor(BaseModel):

    path: Path
    source: bytes
    source_text: str
    lines: list[str]
    visited_node_ids: set[str] = Field(default_factory=set)

    def __get_snippet(self, node: TSNode) -> str:
        """Extract the source code snippet for a given Tree-sitter node."""
        start_byte = node.start_byte
        end_byte = node.end_byte
        return self.source[start_byte:end_byte].decode("utf-8")

    def __count_tokens(self, node: TSNode) -> int:
        # TODO: Replace with proper tokenizer for accurate token count
        return len(self.__get_snippet(node).split()) // 3

    def __iter_identifiers(self, node: TSNode) -> Iterator[TSNode]:
        if node.type == "identifier":
            yield node
        for child in node.children:
            yield from self.__iter_identifiers(child)

    def __get_node_id(self, type_: NodeType, module_name: str, node: TSNode) -> NodeID:
        """Generate a unique identifier for the node based on its position."""
        return NodeID.create(type_, module_name, str(self.path), node.start_byte)

    def process(self, node: TSNode, block_level: int = 0) -> ParserResult:
        """Process a tree-sitter node and its children."""

        nodes: dict[NodeID, Node] = {}
        edges: list[RelationshipBase] = []

        if node.type == "function_definition":
            return self._process_function(node)
        if node.type == "class_definition":
            class_node, (nodes, edges) = self._process_class(node)

            for node_id in nodes.keys():
                edges.append(
                    DataFlowDefinedBy(
                        src=class_node.identifier,
                        dst=node_id,
                        type=DataFlowRelationshipType.DEFINED_BY,
                        operation=DefinitionOperation.ASSIGNMENT,
                    )
                )
            nodes[class_node.identifier] = class_node
            return (nodes, edges)
        # # I'm not sure, should we use expression_statement here or assignment?
        # if node.type == ProcessableNodeTypes.ASSIGNMENT:
        #     return self._process_assignment(node)
        # if node.type == "import_statement":
        #     self._process_import(node)
        #     return
        # if node.type == "import_from_statement":
        #     self._process_import_from(node)
        #     return
        # if node.type == "call":
        #     self._process_call(node)
        #     return

        child_level = block_level
        if node.type in CODE_BLOCK_TYPES:
            # self._process_code_block(node, CODE_BLOCK_TYPES[node.type], block_level)
            child_level = block_level + 1

        for child in node.children:
            _nodes, _edges = self.process(child, child_level)
            nodes.update(_nodes)
            edges.extend(_edges)
        return (nodes, edges)

    def _process_function(self, node: TSNode) -> ParserResult:
        """Process a function definition."""
        nodes: dict[NodeID, Node] = {}
        edges: list[RelationshipBase] = []

        name_node = node.child_by_field_name("name")
        if not name_node:
            return (nodes, edges)

        name = self.__get_snippet(name_node)
        # TODO: Implement module_name extraction
        # module_name = f"{name}"
        # parameter_nodes = self.__collect_parameter_identifiers(
        #     node.child_by_field_name("parameters")
        # )

        node_id = self.__get_node_id(NodeType.FUNCTION, name, node)
        function_node = FunctionNode(
            identifier=node_id,
            name=name,
            # module_name=module_name,#qual,
            # code=self.__get_snippet(node),
            # signature=self.__extract_signature(node.child_by_field_name("parameters")),
            line_start=node.start_point[0] + 1,
            line_end=node.end_point[0] + 1,
            file_path=self.path,
            token_count=self.__count_tokens(node),
            # num_parameters=len(parameter_nodes),
            # has_decorators=self._has_decorators(node),
        )
        nodes[node_id] = function_node
        self.visited_node_ids.add(node_id)

        return (nodes, edges)

    def _process_class(self, node: TSNode) -> tuple[Node, ParserResult]:
        """Process a class definition."""
        nodes: dict[NodeID, Node] = {}
        edges: list[RelationshipBase] = []

        name_node = node.child_by_field_name("name")
        if not name_node:
            raise ValueError(
                f"Class node missing name field. Node Byte Range: {node.byte_range}, Path: {self.path}"
            )

        name = self.__get_snippet(name_node)
        node_id = self.__get_node_id(NodeType.CLASS, name, node)

        line_start = name_node.start_point[0] + 1
        line_end = name_node.end_point[0] + 1
        # it possible that class has superclasses, so we need to extend line_end
        superclasses_node = node.child_by_field_name("superclasses")
        if superclasses_node:
            line_end = superclasses_node.end_point[0] + 1

        class_node = ClassNode(
            identifier=node_id,
            name=name,
            # qualified_name=qual,
            file_path=self.path,
            line_start=line_start,
            line_end=line_end,
            # bases=self._extract_class_bases(node),
        )
        self.visited_node_ids.add(node_id)

        for children in node.children:
            if children.type not in ProcessableNodeTypes:
                continue
            child_nodes, child_edges = self.process(children, block_level=1)
            nodes.update(child_nodes)
            edges.extend(child_edges)

        return (class_node, (nodes, edges))

    # def _process_assignment(self, node: TSNode) -> ParserResult:
    #     """Process an expression statement."""
    #     pass
