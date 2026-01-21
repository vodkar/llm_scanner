from collections.abc import Iterator
from enum import StrEnum
import logging
from pathlib import Path
from pydantic import BaseModel, Field, PrivateAttr

from tree_sitter import Node as TSNode

from models.base import NodeID
from models.edges.base import RelationshipBase
from models.edges.data_flow import (
    DataFlowDefinedBy,
    DataFlowFlowsTo,
    DataFlowRelationshipType,
    DefinitionOperation,
)
from models.edges.call_graph import CallGraphCalledBy, CallGraphCalls
from models.nodes import CallNode, CodeBlockNode, Node, VariableNode
from models.nodes.base import NodeType
from models.nodes.code import ClassNode, FunctionNode
from services.cpg_parser.types import ParserResult


logger = logging.getLogger(__name__)


def _caller_stack_factory() -> list[NodeID]:
    """Create a new caller stack list.

    Returns:
        A new list for tracking caller node identifiers.
    """

    return []


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

    __scope_stack: list[dict[str, NodeID]] = PrivateAttr(default_factory=lambda: [{}])
    __caller_stack: list[NodeID] = PrivateAttr(default_factory=_caller_stack_factory)

    def __normalize_name(self, raw: str) -> str:
        """Normalize a name extracted from source code.

        Args:
            raw: Raw text extracted from the source.

        Returns:
            Normalized name with collapsed whitespace.
        """

        return " ".join(raw.split())

    def __push_scope(self) -> None:
        self.__scope_stack.append({})

    def __pop_scope(self) -> None:
        if len(self.__scope_stack) <= 1:
            return
        self.__scope_stack.pop()

    def __push_caller(self, node_id: NodeID) -> None:
        self.__caller_stack.append(node_id)

    def __pop_caller(self) -> None:
        if not self.__caller_stack:
            return
        self.__caller_stack.pop()

    def __current_caller_id(self) -> NodeID | None:
        if not self.__caller_stack:
            return None
        return self.__caller_stack[-1]

    def __bind_symbol(self, name: str, node_id: NodeID) -> None:
        normalized = self.__normalize_name(name)
        if not normalized:
            return
        self.__scope_stack[-1][normalized] = node_id

    def __resolve_symbol(self, name: str) -> NodeID | None:
        normalized = self.__normalize_name(name)
        for scope in reversed(self.__scope_stack):
            node_id = scope.get(normalized)
            if node_id:
                return node_id
        return None

    def __get_snippet(self, node: TSNode) -> str:
        """Extract the source code snippet for a given Tree-sitter node."""
        start_byte = node.start_byte
        end_byte = node.end_byte
        return self.source[start_byte:end_byte].decode("utf-8")

    def __count_tokens(self, node: TSNode) -> int:
        # TODO: Replace with proper tokenizer for accurate token count
        return len(self.__get_snippet(node).split()) // 3

    def __is_top_level_statement(self, node: TSNode) -> bool:
        if not node.parent or node.parent.type != "module":
            return False
        if not node.is_named:
            return False
        if node.type in {
            "module",
            "function_definition",
            "class_definition",
            "import_statement",
            "import_from_statement",
            "decorated_definition",
        }:
            return False
        return True

    def __iter_top_level_blocks(self, module_node: TSNode) -> list[list[TSNode]]:
        blocks: list[list[TSNode]] = []
        current_block: list[TSNode] = []

        for child in module_node.children:
            if self.__is_top_level_statement(child):
                current_block.append(child)
                continue

            if current_block:
                blocks.append(current_block)
                current_block = []

        if current_block:
            blocks.append(current_block)

        return blocks

    def __top_level_block_name(self, nodes: list[TSNode]) -> str:
        first_node: TSNode = nodes[0]
        line_index: int = first_node.start_point[0]
        if 0 <= line_index < len(self.lines):
            return self.__normalize_name(self.lines[line_index].strip())

        snippet: str = self.__get_snippet(first_node)
        first_line: str = snippet.splitlines()[0] if snippet else ""
        return self.__normalize_name(first_line.strip())

    def __create_code_block_node(self, nodes: list[TSNode]) -> CodeBlockNode:
        first_node: TSNode = nodes[0]
        last_node: TSNode = nodes[-1]
        start_line: int = first_node.start_point[0]
        end_line: int = last_node.end_point[0]
        block_name: str = self.__top_level_block_name(nodes)
        node_id: NodeID = NodeID.create(
            "code_block",
            block_name,
            str(self.path),
            first_node.start_byte,
        )
        return CodeBlockNode(
            identifier=node_id,
            line_start=start_line + 1,
            line_end=end_line + 1,
            file_path=self.path,
        )

    def __register_top_level_symbols(self, module_node: TSNode) -> None:
        """Register top-level function and class symbols before traversal.

        This allows call resolution for functions/classes defined later in the file.
        """

        for child in module_node.children:
            if child.type not in {"function_definition", "class_definition"}:
                continue
            name_node = child.child_by_field_name("name")
            if not name_node:
                continue
            name = self.__normalize_name(self.__get_snippet(name_node))
            node_type: NodeType = (
                NodeType.FUNCTION
                if child.type == "function_definition"
                else NodeType.CLASS
            )
            node_id = self.__get_node_id(node_type, name, child)
            self.__bind_symbol(name, node_id)

    def __iter_identifiers(self, node: TSNode) -> Iterator[TSNode]:
        if node.type == "identifier":
            yield node
        for child in node.children:
            yield from self.__iter_identifiers(child)

    def __iter_calls(self, node: TSNode) -> Iterator[TSNode]:
        if node.type == "call":
            yield node
        for child in node.children:
            yield from self.__iter_calls(child)

    def __iter_source_atoms(self, node: TSNode) -> Iterator[tuple[str, str, TSNode]]:
        """Yield atomic value sources (variables, attributes, calls).

        Notes:
            - For attribute nodes, we treat the full dotted expression as one symbol
              (e.g. "self.x") to avoid splitting into identifiers.
            - For call nodes, we yield the call itself *and* recurse into its children
              so that argument dependencies are still captured.
        """

        if node.type == "identifier":
            yield ("identifier", self.__normalize_name(self.__get_snippet(node)), node)
            return
        if node.type == "attribute":
            yield ("attribute", self.__normalize_name(self.__get_snippet(node)), node)
            return
        if node.type == "call":
            yield ("call", self.__normalize_name(self.__get_snippet(node)), node)

            # Only recurse into arguments (and other children), but skip the callee
            # itself so we don't treat the function name as a value source.
            callee = node.child_by_field_name("function")
            for child in node.children:
                if callee is not None and child == callee:
                    continue
                yield from self.__iter_source_atoms(child)
            return

        for child in node.children:
            yield from self.__iter_source_atoms(child)

    def __iter_argument_atoms(self, node: TSNode) -> Iterator[tuple[str, str, TSNode]]:
        """Yield argument-level sources for a call.

        Unlike __iter_source_atoms, this treats nested calls as atomic so we only
        capture *direct* argument expressions passed to the call.
        """

        # keyword_argument := <name>=<value>
        if node.type == "keyword_argument":
            value = node.child_by_field_name("value")
            if value is not None:
                yield from self.__iter_argument_atoms(value)
            return

        if node.type == "identifier":
            yield ("identifier", self.__normalize_name(self.__get_snippet(node)), node)
            return
        if node.type == "attribute":
            yield ("attribute", self.__normalize_name(self.__get_snippet(node)), node)
            return
        if node.type == "call":
            yield ("call", self.__normalize_name(self.__get_snippet(node)), node)
            return

        for child in node.children:
            yield from self.__iter_argument_atoms(child)

    def __add_argument_dataflow_edges(
        self,
        *,
        call_ts_node: TSNode,
        call_node_id: NodeID,
        caller_id: NodeID,
        nodes: dict[NodeID, Node],
        edges: list[RelationshipBase],
    ) -> None:
        """Add DataFlowFlowsTo edges from argument sources to a call node."""

        arguments_node = call_ts_node.child_by_field_name("arguments")
        if arguments_node is None:
            return

        seen_sources: set[NodeID] = set()
        source_ids: list[NodeID] = []

        for kind, text, atom in self.__iter_argument_atoms(arguments_node):
            if not text:
                continue

            if kind in {"identifier", "attribute"}:
                resolved = self.__resolve_symbol(text)
                if resolved is not None:
                    if resolved not in seen_sources:
                        source_ids.append(resolved)
                        seen_sources.add(resolved)
                    continue

                ref = self.__create_variable_node(
                    kind="variable_ref", name=text, node=atom
                )
                if ref.identifier not in seen_sources:
                    nodes[ref.identifier] = ref
                    self.visited_node_ids.add(ref.identifier)
                    source_ids.append(ref.identifier)
                    seen_sources.add(ref.identifier)
                continue

            if kind == "call":
                nested_target_id = self.__resolve_call_target(atom)
                if nested_target_id is None:
                    self.__warn_unresolved_call(atom)
                    continue

                nested_call_node: CallNode = self.__create_call_node(
                    call_node=atom,
                    caller_id=caller_id,
                    callee_id=nested_target_id,
                )
                if nested_call_node.identifier not in nodes:
                    nodes[nested_call_node.identifier] = nested_call_node
                    self.visited_node_ids.add(nested_call_node.identifier)
                    self.__add_call_edges(
                        edges=edges,
                        caller_id=caller_id,
                        call_id=nested_call_node.identifier,
                        callee_id=nested_target_id,
                    )

                if nested_call_node.identifier not in seen_sources:
                    source_ids.append(nested_call_node.identifier)
                    seen_sources.add(nested_call_node.identifier)
                continue

        for src_id in source_ids:
            edges.append(
                DataFlowFlowsTo(
                    src=src_id,
                    dst=call_node_id,
                )
            )

    def __resolve_call_target(self, call_node: TSNode) -> NodeID | None:
        """Resolve a call node's callee to a known FunctionNode identifier."""

        function_node = call_node.child_by_field_name("function")
        if not function_node:
            return None

        if function_node.type == "identifier":
            name = self.__normalize_name(self.__get_snippet(function_node))
            resolved = self.__resolve_symbol(name)
            if resolved and str(resolved).startswith("function:"):
                return resolved
        return None

    def __warn_unresolved_call(self, call_node: TSNode) -> None:
        snippet: str = self.__normalize_name(self.__get_snippet(call_node))
        line_number: int = call_node.start_point[0] + 1
        logger.warning(
            f"Unresolved call target for '{snippet}' at {self.path}:{line_number}"
        )

    def __create_call_node(
        self, *, call_node: TSNode, caller_id: NodeID, callee_id: NodeID
    ) -> CallNode:
        snippet: str = self.__normalize_name(self.__get_snippet(call_node))
        call_id: NodeID = NodeID.create(
            "call",
            snippet,
            str(self.path),
            call_node.start_byte,
        )
        return CallNode(
            identifier=call_id,
            caller_id=caller_id,
            callee_id=callee_id,
            line_start=call_node.start_point[0] + 1,
            line_end=call_node.end_point[0] + 1,
            file_path=self.path,
        )

    def __add_call_edges(
        self,
        *,
        edges: list[RelationshipBase],
        caller_id: NodeID,
        call_id: NodeID,
        callee_id: NodeID,
    ) -> None:
        edges.append(
            CallGraphCalls(
                src=caller_id,
                dst=call_id,
                is_direct=True,
                call_depth=0,
            )
        )
        edges.append(
            CallGraphCalledBy(
                src=call_id,
                dst=callee_id,
            )
        )

    def __collect_parameter_identifiers(
        self, parameters_node: TSNode | None
    ) -> list[TSNode]:
        """Collect distinct parameter identifier nodes in source order."""

        if not parameters_node:
            return []

        identifiers: list[TSNode] = []
        for child in parameters_node.children:
            identifiers.extend(self.__iter_identifiers(child))

        seen: set[tuple[int, int]] = set()
        ordered: list[TSNode] = []
        for ident in identifiers:
            key = (ident.start_byte, ident.end_byte)
            if key in seen:
                continue
            seen.add(key)
            ordered.append(ident)

        return ordered

    def __iter_assignment_targets(self, node: TSNode) -> Iterator[tuple[str, TSNode]]:
        """Iterate assignment targets on the LHS.

        This supports simple identifiers, attributes (e.g. self.x), subscripts (e.g. a[i]),
        and destructuring (e.g. a, b = ...).
        """

        if node.type in {"identifier", "subscript"}:
            yield (self.__normalize_name(self.__get_snippet(node)), node)
            return

        if node.type == "attribute":
            yield (self.__normalize_name(self.__get_snippet(node)), node)
            return

        for child in node.children:
            yield from self.__iter_assignment_targets(child)

    def __create_variable_node(
        self,
        *,
        kind: str,
        name: str,
        node: TSNode,
        type_hint: str = "",
    ) -> VariableNode:
        """Create a VariableNode for a definition or reference."""

        normalized_name = self.__normalize_name(name)
        node_id = NodeID.create(kind, normalized_name, str(self.path), node.start_byte)
        variable_node = VariableNode(
            identifier=node_id,
            name=normalized_name,
            type_hint=type_hint,
            line_start=node.start_point[0] + 1,
            line_end=node.end_point[0] + 1,
            file_path=self.path,
        )
        return variable_node

    def __get_or_create_defined_variable(
        self,
        *,
        name: str,
        node: TSNode,
        type_hint: str = "",
    ) -> tuple[NodeID, VariableNode | None]:
        """Get an existing variable symbol or create it in the current scope.

        This keeps a single VariableNode per symbol (per scope) so that references
        like `b = a + 1` resolve to the same `a` node that was created by `a = ...`.
        """

        normalized = self.__normalize_name(name)
        existing = self.__scope_stack[-1].get(normalized)
        if existing:
            return existing, None

        var = self.__create_variable_node(
            kind="variable",
            name=normalized,
            node=node,
            type_hint=type_hint,
        )
        self.__bind_symbol(normalized, var.identifier)
        return var.identifier, var

    def __get_node_id(self, type_: NodeType, module_name: str, node: TSNode) -> NodeID:
        """Generate a unique identifier for the node based on its position."""
        return NodeID.create(type_, module_name, str(self.path), node.start_byte)

    def process(self, node: TSNode, block_level: int = 0) -> ParserResult:
        """Process a tree-sitter node and its children."""

        nodes: dict[NodeID, Node] = {}
        edges: list[RelationshipBase] = []

        if node.type == "module":
            top_level_blocks: list[list[TSNode]] = self.__iter_top_level_blocks(node)
            for block_nodes in top_level_blocks:
                code_block: CodeBlockNode = self.__create_code_block_node(block_nodes)
                nodes[code_block.identifier] = code_block
                self.visited_node_ids.add(code_block.identifier)

            self.__register_top_level_symbols(node)

            for child in node.children:
                if self.__is_top_level_statement(child):
                    continue
                child_nodes, child_edges = self.process(child, block_level)
                nodes.update(child_nodes)
                edges.extend(child_edges)

            for block_nodes in top_level_blocks:
                code_block_id: NodeID = NodeID.create(
                    "code_block",
                    self.__top_level_block_name(block_nodes),
                    str(self.path),
                    block_nodes[0].start_byte,
                )
                self.__push_caller(code_block_id)
                for block_node in block_nodes:
                    block_nodes_nodes, block_nodes_edges = self.process(
                        block_node, block_level=1
                    )
                    nodes.update(block_nodes_nodes)
                    edges.extend(block_nodes_edges)
                self.__pop_caller()
            return (nodes, edges)

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
        if node.type in {"assignment", "augmented_assignment", "annotated_assignment"}:
            return self._process_assignment(node)
        if node.type == "call":
            return self._process_call(node)
        # if node.type == "import_statement":
        #     self._process_import(node)
        #     return
        # if node.type == "import_from_statement":
        #     self._process_import_from(node)
        #     return
        # if node.type == "call":
        #     self._process_call(node)
        #     return

        for child in node.children:
            _nodes, _edges = self.process(child, block_level)
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

        name = self.__normalize_name(self.__get_snippet(name_node))

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
            # token_count=self.__count_tokens(node),
            # num_parameters=len(parameter_nodes),
            # has_decorators=self._has_decorators(node),
        )
        nodes[node_id] = function_node
        self.visited_node_ids.add(node_id)

        # Bind the function name in the enclosing scope so call sites can resolve it.
        self.__bind_symbol(name, node_id)

        self.__push_scope()
        self.__push_caller(function_node.identifier)

        parameter_nodes = self.__collect_parameter_identifiers(
            node.child_by_field_name("parameters")
        )
        for param in parameter_nodes:
            param_name = self.__normalize_name(self.__get_snippet(param))
            param_type = ""
            parent = param.parent
            if parent:
                annotation = parent.child_by_field_name("type")
                if annotation:
                    param_type = self.__normalize_name(self.__get_snippet(annotation))

            param_var = self.__create_variable_node(
                kind="variable",
                name=param_name,
                node=param,
                type_hint=param_type,
            )
            nodes[param_var.identifier] = param_var
            self.visited_node_ids.add(param_var.identifier)
            self.__bind_symbol(param_var.name, param_var.identifier)
            edges.append(
                DataFlowDefinedBy(
                    src=function_node.identifier,
                    dst=param_var.identifier,
                    type=DataFlowRelationshipType.DEFINED_BY,
                    operation=DefinitionOperation.PARAMETER,
                )
            )

        body_node = node.child_by_field_name("body")
        if body_node:
            for child in body_node.children:
                child_nodes, child_edges = self.process(child, block_level=1)
                nodes.update(child_nodes)
                edges.extend(child_edges)

        self.__pop_caller()
        self.__pop_scope()

        return (nodes, edges)

    def _process_call(self, node: TSNode) -> ParserResult:
        """Process a call expression within a function."""

        nodes: dict[NodeID, Node] = {}
        edges: list[RelationshipBase] = []

        caller_id: NodeID | None = self.__current_caller_id()
        if caller_id is None:
            return (nodes, edges)

        callee_id: NodeID | None = self.__resolve_call_target(node)
        if callee_id is None:
            self.__warn_unresolved_call(node)
            return (nodes, edges)

        call_node: CallNode = self.__create_call_node(
            call_node=node,
            caller_id=caller_id,
            callee_id=callee_id,
        )
        nodes[call_node.identifier] = call_node
        self.visited_node_ids.add(call_node.identifier)
        self.__add_call_edges(
            edges=edges,
            caller_id=caller_id,
            call_id=call_node.identifier,
            callee_id=callee_id,
        )

        self.__add_argument_dataflow_edges(
            call_ts_node=node,
            call_node_id=call_node.identifier,
            caller_id=caller_id,
            nodes=nodes,
            edges=edges,
        )

        for child in node.children:
            child_nodes, child_edges = self.process(child, block_level=1)
            nodes.update(child_nodes)
            edges.extend(child_edges)
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

        # Bind the class name in the enclosing scope so it can be resolved when
        # passed as an argument (e.g. foo(MyClass)).
        self.__bind_symbol(self.__normalize_name(name), node_id)

        for children in node.children:
            if children.type not in ProcessableNodeTypes:
                continue
            child_nodes, child_edges = self.process(children, block_level=1)
            nodes.update(child_nodes)
            edges.extend(child_edges)

        return (class_node, (nodes, edges))

    def _process_assignment(self, node: TSNode) -> ParserResult:
        """Process an assignment and emit variable nodes and data-flow edges.

        This creates VariableNode objects for assignment targets and for detected
        value sources (variables, calls). It then adds
        DataFlowDefinedBy edges from each value source to each assignment target.
        """

        nodes: dict[NodeID, Node] = {}
        edges: list[RelationshipBase] = []

        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if not left or not right:
            return (nodes, edges)

        type_hint = ""
        annotation = node.child_by_field_name("type")
        if annotation:
            type_hint = self.__normalize_name(self.__get_snippet(annotation))

        targets = list(self.__iter_assignment_targets(left))
        if not targets:
            return (nodes, edges)

        source_ids: list[NodeID] = []
        seen_source_ids: set[NodeID] = set()

        for kind, text, atom in self.__iter_source_atoms(right):
            if not text:
                continue

            if kind in {"identifier", "attribute"}:
                resolved = self.__resolve_symbol(text)
                if resolved:
                    if resolved not in seen_source_ids:
                        source_ids.append(resolved)
                        seen_source_ids.add(resolved)
                    continue

                # Unresolved symbol (e.g. builtins, imported names, forward refs).
                ref = self.__create_variable_node(
                    kind="variable_ref", name=text, node=atom
                )
                if ref.identifier not in seen_source_ids:
                    nodes[ref.identifier] = ref
                    self.visited_node_ids.add(ref.identifier)
                    source_ids.append(ref.identifier)
                    seen_source_ids.add(ref.identifier)
                continue

            if kind == "call":
                caller_id: NodeID | None = self.__current_caller_id()
                if caller_id is None:
                    continue

                target_id: NodeID | None = self.__resolve_call_target(atom)
                if target_id is None:
                    self.__warn_unresolved_call(atom)
                    continue

                call_node: CallNode = self.__create_call_node(
                    call_node=atom,
                    caller_id=caller_id,
                    callee_id=target_id,
                )
                if call_node.identifier not in seen_source_ids:
                    nodes[call_node.identifier] = call_node
                    self.visited_node_ids.add(call_node.identifier)
                    source_ids.append(call_node.identifier)
                    seen_source_ids.add(call_node.identifier)

                self.__add_call_edges(
                    edges=edges,
                    caller_id=caller_id,
                    call_id=call_node.identifier,
                    callee_id=target_id,
                )

                self.__add_argument_dataflow_edges(
                    call_ts_node=atom,
                    call_node_id=call_node.identifier,
                    caller_id=caller_id,
                    nodes=nodes,
                    edges=edges,
                )
                continue

        if not source_ids:
            # Pure literal/expression assignment: no data-flow sources to link.
            source_ids = []

        # Augmented assignments (e.g. x += 1) also depend on the previous target value.
        if node.type == "augmented_assignment":
            for target_name, _target_node in targets:
                resolved_prev = self.__resolve_symbol(target_name)
                if resolved_prev and resolved_prev not in seen_source_ids:
                    source_ids.append(resolved_prev)
                    seen_source_ids.add(resolved_prev)
                    continue

                src_prev = self.__create_variable_node(
                    kind="variable_ref",
                    name=target_name,
                    node=node,
                )
                if src_prev.identifier not in seen_source_ids:
                    nodes[src_prev.identifier] = src_prev
                    self.visited_node_ids.add(src_prev.identifier)
                    source_ids.append(src_prev.identifier)
                    seen_source_ids.add(src_prev.identifier)

        for target_name, target_node in targets:
            dst_id, created = self.__get_or_create_defined_variable(
                name=target_name,
                node=target_node,
                type_hint=type_hint,
            )
            if created:
                nodes[created.identifier] = created
                self.visited_node_ids.add(created.identifier)

            for src_id in source_ids:
                edges.append(
                    DataFlowDefinedBy(
                        src=src_id,
                        dst=dst_id,
                        type=DataFlowRelationshipType.DEFINED_BY,
                        operation=DefinitionOperation.ASSIGNMENT,
                    )
                )

        return (nodes, edges)
