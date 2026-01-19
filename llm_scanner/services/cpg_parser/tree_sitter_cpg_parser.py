# type: ignore

from pathlib import Path
from typing import Callable, Iterable, Iterator, Optional

import tree_sitter_python as tspython
from tree_sitter import Language, Parser, Node as TSNode

from models.base import NodeID
from models.edges import Edge, EdgeType
from models.nodes import (
    ClassNode,
    CodeBlockNode,
    DeprecatedNode,
    FunctionNode,
    ModuleNode,
    Node,
    NodeType,
    VariableNode,
    VariableScope,
)

# from models.parser.source_file import SourceFile
from services.cpg_parser.consts import (
    COMPLEXITY_NODES,
    SENSITIVE_NAMES,
    USER_INPUT_NAMES,
)

from .cpg_parser_interface import CPGParserProtocol


class TreeSitterCPGParser(CPGParserProtocol):
    """CPG parser implementation using py-tree-sitter."""

    def __init__(self):
        self.language = Language(tspython.language())
        self.parser = Parser(self.language)

    def parse_file(
        self, path: Path, ignore_magic: bool = True
    ) -> tuple[dict[str, Node], list[Edge]]:
        """Parse a single file using tree-sitter into structured nodes.

        Args:
            path: Path to the Python file to parse
            ignore_magic: Whether to ignore magic methods (__init__, __str__, etc.)

        Returns:
            Tuple of (nodes_dict, edges_list)

        Raises:
            ValueError: If file cannot be read or path is invalid
        """
        if not path.exists():
            raise ValueError(f"File does not exist: {path}")
        if not path.is_file():
            raise ValueError(f"Path is not a file: {path}")
        if path.suffix != ".py":
            raise ValueError(f"File is not a Python file: {path}")

        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            raise ValueError(f"Failed to read file {path}: {e}") from e

        try:
            module_name = path.stem
            builder = TreeSitterCPGBuilder(
                source,
                str(path),
                self.parser,
                ignore_magic=ignore_magic,
                module_name=module_name,
            )
            return builder.build_structured()
        except Exception as e:
            raise ValueError(f"Failed to parse file {path}: {e}") from e

    def parse_project(
        self, root: Path, ignore_magic: bool = True
    ) -> tuple[dict[str, Node], list[Edge]]:
        """Parse a project directory using tree-sitter into structured nodes.

        Args:
            root: Root directory of the project
            ignore_magic: Whether to ignore magic methods

        Returns:
            Tuple of (nodes_dict, edges_list)

        Raises:
            ValueError: If directory cannot be accessed or is invalid
        """
        if not root.exists():
            raise ValueError(f"Directory does not exist: {root}")
        if not root.is_dir():
            raise ValueError(f"Path is not a directory: {root}")

        try:
            builder = TreeSitterProjectCPGBuilder(
                root, self.parser, ignore_magic=ignore_magic
            )
            return builder.build_structured()
        except Exception as e:
            raise ValueError(f"Failed to parse project {root}: {e}") from e


class TreeSitterCPGBuilder:
    """Build a CPG using tree-sitter for a single file."""

    def __init__(
        self,
        source: str,
        file: str,
        parser: Parser,
        ignore_magic: bool = True,
        module_name: str | None = None,
    ):
        self.source = source
        self.file = file
        self.parser = parser
        self.ignore_magic = ignore_magic
        self.module_name = module_name or Path(file).stem

        self.nodes: dict[str, DeprecatedNode] = {}
        self.edges: list[Edge] = []
        self.pending_calls: list[tuple[str, str]] = []
        self.structured_nodes: dict[str, Node] = {}
        self.module_import_list: set[str] = set()
        self.module_exports: set[str] = set()

        # Symbol resolution tables
        self.func_index: dict[str, str] = {}  # qualname -> node_id
        self.class_index: dict[str, str] = {}
        self.module_imports: dict[str, str] = {}  # bound name -> module/symbol

        # Current scope tracking
        self.current_stack: list[str] = []
        self.scope_qual: list[str] = []

        # Parse the source
        self.tree = self.parser.parse(bytes(source, "utf8"))
        self._lines = source.splitlines()
        self._built = False

        # self._current_file = SourceFile(path=Path(self.file), tree=self.tree)

    def _snippet(self, node: TSNode) -> str:
        """Extract the code snippet for a tree-sitter node.

        Args:
            node: The tree-sitter node

        Returns:
            The code snippet as a string
        """
        start_line = node.start_point[0]
        end_line = node.end_point[0]
        return "\n".join(self._lines[start_line : end_line + 1])

    def _new_node(self, type_: NodeType, name: str, qualname: str, node: TSNode) -> str:
        """Create a new CPG node and add it to the nodes dictionary.

        Args:
            type_: The node type
            name: The node name
            qualname: The fully qualified name
            node: The tree-sitter node

        Returns:
            The unique node ID
        """
        node_id = (
            f"{type_.value.lower()}:{qualname}@{self.file}:{node.start_point[0] + 1}"
        )
        n = DeprecatedNode(
            id=node_id,
            type=type_,
            name=name,
            qualname=qualname,
            file=self.file,
            lineno=node.start_point[0] + 1,
            end_lineno=node.end_point[0] + 1,
            code=self._snippet(node),
        )
        self.nodes[node_id] = n
        return node_id

    def _push(self, node_id: str, name: str):
        self.current_stack.append(node_id)
        self.scope_qual.append(name)

    def _pop(self):
        self.current_stack.pop()
        self.scope_qual.pop()

    def _current(self) -> Optional[DeprecatedNode]:
        return self.nodes.get(self.current_stack[-1]) if self.current_stack else None

    def _qual(self, name: str) -> str:
        if self.scope_qual:
            return ".".join(self.scope_qual + [name])
        return name

    def _check_if_magic(self, name: str) -> bool:
        return self.ignore_magic and name.startswith("__") and name.endswith("__")

    def build(self) -> tuple[dict[str, DeprecatedNode], list[Edge]]:
        """Build CPG from the parsed tree."""

        self._ensure_built()
        return self.nodes, self.edges

    def build_structured(self) -> tuple[dict[str, Node], list[Edge]]:
        """Build structured nodes (Function, Module, CodeBlock, Variable)."""

        self._ensure_built()
        return self.structured_nodes, self.edges

    def _ensure_built(self) -> None:
        if self._built:
            return
        self._run()
        self._built = True

    def _run(self) -> None:
        root = self.tree.root_node
        mod_id = self._new_node(
            NodeType.MODULE, self.module_name.split(".")[-1], self.module_name, root
        )
        self._push(mod_id, self.module_name)
        self._process_node(root)
        self._pop()
        self._register_module_node(mod_id)

    def _register_module_node(self, module_id: str) -> None:
        module_node = ModuleNode(
            identifier=NodeID.create("module", self.module_name, self.file, 1),
            name=self.module_name.split(".")[-1],
            file_path=self.file,
            imports=sorted(self.module_import_list),
            exports=sorted(self.module_exports),
            is_entry_point=self._is_entry_point(),
        )
        self.structured_nodes[module_id] = module_node

    def _is_entry_point(self) -> bool:
        return (
            self.file.endswith("__main__.py")
            or 'if __name__ == "__main__":' in self.source
        )

    def _process_node(self, node: TSNode, block_level: int = 0):
        """Process a tree-sitter node and its children."""
        if node.type == "module":
            self._process_top_level_blocks(node)
        if node.type == "function_definition":
            self._process_function(node)
            return
        if node.type == "class_definition":
            self._process_class(node)
            return
        if node.type == "import_statement":
            self._process_import(node)
            return
        if node.type == "import_from_statement":
            self._process_import_from(node)
            return
        if node.type == "call":
            self._process_call(node)
            return

        if node.type == "decorated_definition":
            for child in node.children:
                self._process_node(child, block_level)
            return

        for child in node.children:
            self._process_node(child, block_level)

    def _process_function(self, node: TSNode):
        """Process a function definition."""
        name_node = node.child_by_field_name("name")
        if not name_node:
            return

        name = self._get_text(name_node)
        if self._check_if_magic(name):
            return

        qual = self._qual(name)
        node_id = self._new_node(NodeType.FUNCTION, name, qual, node)
        self.func_index[qual] = node_id
        if len(self.current_stack) == 1:
            self.module_exports.add(qual)

        # Add contains edge
        if self.current_stack:
            self.edges.append(
                Edge(src=self.current_stack[-1], dst=node_id, type=EdgeType.CONTAINS)
            )

        # Collect function parameters
        cur = self.nodes[node_id]
        parameter_nodes = self._collect_parameter_identifiers(
            node.child_by_field_name("parameters")
        )
        for param in parameter_nodes:
            name_text = self._get_text(param)
            cur.locals.add(name_text)
            self._register_variable(
                name=name_text,
                scope=VariableScope.PARAMETER,
                line_number=param.start_point[0] + 1,
                type_hint=self._infer_parameter_annotation(param),
            )

        function_node = FunctionNode(
            name=name,
            module_name=qual,
            code=self._snippet(node),
            signature=self._extract_signature(node.child_by_field_name("parameters")),
            line_start=node.start_point[0] + 1,
            line_end=node.end_point[0] + 1,
            file_path=self.file,
            token_count=self._count_tokens(node),
            cyclomatic_complexity=self._estimate_cyclomatic_complexity(
                node.child_by_field_name("body")
            ),
            num_parameters=len(parameter_nodes),
            has_decorators=self._has_decorators(node),
        )
        self.structured_nodes[node_id] = function_node

        # Process function body
        self._push(node_id, name)
        body_node = node.child_by_field_name("body")
        if body_node:
            self._collect_symbols(body_node, cur)
        self._pop()

    def _process_class(self, node: TSNode):
        """Process a class definition."""
        name_node = node.child_by_field_name("name")
        if not name_node:
            return

        name = self._get_text(name_node)
        if self._check_if_magic(name):
            return

        qual = self._qual(name)
        node_id = self._new_node(NodeType.CLASS, name, qual, node)
        self.class_index[qual] = node_id
        if len(self.current_stack) == 1:
            self.module_exports.add(qual)

        # Add contains edge
        if self.current_stack:
            self.edges.append(
                Edge(src=self.current_stack[-1], dst=node_id, type=EdgeType.CONTAINS)
            )

        class_node = ClassNode(
            name=name,
            qualified_name=qual,
            file_path=self.file,
            line_start=node.start_point[0] + 1,
            line_end=node.end_point[0] + 1,
            bases=self._extract_class_bases(node),
        )
        self.structured_nodes[node_id] = class_node

        # Process class body
        self._push(node_id, name)
        body_node = node.child_by_field_name("body")
        if body_node:
            self._process_node(body_node)
        self._pop()

    def _process_import(self, node: TSNode):
        """Process an import statement."""
        cur = self._current()
        if not cur:
            return

        for child in node.children:
            if child.type == "dotted_name":
                module_name = self._get_text(child)
                cur.imports.add(module_name)
                # Record for resolution
                if cur.type == NodeType.MODULE:
                    self.module_imports[module_name.split(".")[0]] = module_name
                    self.module_import_list.add(module_name)
            elif child.type == "aliased_import":
                name_node = child.child_by_field_name("name")
                alias_node = child.child_by_field_name("alias")
                if name_node and alias_node:
                    module_name = self._get_text(name_node)
                    alias = self._get_text(alias_node)
                    cur.imports.add(alias)
                    if cur.type == NodeType.MODULE:
                        self.module_imports[alias] = module_name
                        self.module_import_list.add(alias)

    def _process_import_from(self, node: TSNode):
        """Process a from...import statement."""
        cur = self._current()
        if not cur:
            return

        module_node = node.child_by_field_name("module_name")
        raw_module_name = self._get_text(module_node) if module_node else ""
        module_name = self._resolve_module_name(raw_module_name)

        def register_import(target: str, alias: str | None = None) -> None:
            canonical = f"{module_name}.{target}" if module_name else target
            cur.imports.add(canonical)
            if cur.type == NodeType.MODULE:
                bound = alias or target.split(".")[-1]
                self.module_imports[bound] = canonical
                self.module_import_list.add(canonical)

        # Find imported names
        for child in node.children:
            if child is module_node or child.type in {"from", "import"}:
                continue
            if child.type == "import_list":
                for import_child in child.children:
                    self._handle_import_from_child(import_child, register_import)
            else:
                self._handle_import_from_child(child, register_import)

    def _handle_import_from_child(
        self,
        child: TSNode,
        register: Callable[[str, str | None], None],
    ) -> None:
        if child.type in {"dotted_name", "identifier"}:
            register(self._get_text(child), None)
        elif child.type == "aliased_import":
            name_node = child.child_by_field_name("name")
            alias_node = child.child_by_field_name("alias")
            if not name_node:
                return
            alias = self._get_text(alias_node) if alias_node else None
            register(self._get_text(name_node), alias)

    def _process_call(self, node: TSNode):
        """Process a function call."""
        cur = self._current()
        if not cur:
            return

        function_node = node.child_by_field_name("function")
        if not function_node:
            return

        callee_qual = self._resolve_call_qualname(function_node)
        if not callee_qual:
            return

        # Try local resolution
        if callee_qual in self.func_index:
            self.edges.append(
                Edge(src=cur.id, dst=self.func_index[callee_qual], type=EdgeType.CALLS)
            )
        else:
            # Store for cross-file resolution
            self.pending_calls.append((cur.id, callee_qual))

    def _process_top_level_blocks(self, module_node: TSNode) -> None:
        blocks: list[list[TSNode]] = []
        current_block: list[TSNode] = []

        for child in module_node.children:
            if self._is_top_level_statement(child):
                current_block.append(child)
                continue

            if current_block:
                blocks.append(current_block)
                current_block = []

        if current_block:
            blocks.append(current_block)

        for block_nodes in blocks:
            self._process_top_level_block(block_nodes)

    def _process_top_level_block(self, nodes: list[TSNode]) -> None:
        first_node: TSNode = nodes[0]
        last_node: TSNode = nodes[-1]
        start_line: int = first_node.start_point[0]
        end_line: int = last_node.end_point[0]
        code: str = "\n".join(self._lines[start_line : end_line + 1])
        block_name: str = self._lines[start_line].strip() if self._lines else ""
        block_id = NodeID.create(
            "code_block",
            block_name,
            self.file,
            first_node.start_byte,
        )
        block_node = CodeBlockNode(
            identifier=block_id,
            line_start=start_line + 1,
            line_end=end_line + 1,
            file_path=self.file,
            # token_count=self._count_tokens(first_node),
        )
        self.structured_nodes[str(block_id)] = block_node

    def _collect_symbols(self, node: TSNode, cur: DeprecatedNode, block_level: int = 0):
        """Collect symbols (locals, globals, imports, calls) from node tree."""
        child_level = block_level
        if node.type in {"assignment", "augmented_assignment"}:
            # Collect assigned variables
            left = node.child_by_field_name("left")
            if left:
                for target_name, target_node, is_attr in self._iter_assignment_targets(
                    left
                ):
                    if cur.type == NodeType.FUNCTION:
                        cur.locals.add(target_name)
                        scope = (
                            VariableScope.ATTRIBUTE if is_attr else VariableScope.LOCAL
                        )
                    else:
                        scope = VariableScope.GLOBAL
                    self._register_variable(
                        name=target_name,
                        scope=scope,
                        line_number=target_node.start_point[0] + 1,
                    )
        elif node.type == "global_statement":
            # Collect global declarations
            for child in node.children:
                if child.type == "identifier":
                    cur.globals.add(self._get_text(child))
                    self._register_variable(
                        name=self._get_text(child),
                        scope=VariableScope.GLOBAL,
                        line_number=child.start_point[0] + 1,
                    )
        elif node.type == "call":
            self._process_call(node)
        elif node.type in ("import_statement", "import_from_statement"):
            if node.type == "import_statement":
                self._process_import(node)
            else:
                self._process_import_from(node)

        # Recursively process children
        for child in node.children:
            self._collect_symbols(child, cur, block_level)

    def _is_top_level_statement(self, node: TSNode) -> bool:
        if not node.parent or node.parent.type != "module":
            return False
        if node.type in {
            "function_definition",
            "class_definition",
            "import_statement",
            "import_from_statement",
            "decorated_definition",
        }:
            return False
        return True

    def _resolve_call_qualname(self, func_node: TSNode) -> str | None:
        """Resolve a function call to its qualified name."""
        if func_node.type == "identifier":
            name = self._get_text(func_node)
            # Try to resolve in current scope
            for i in range(len(self.scope_qual), -1, -1):
                qual = ".".join(self.scope_qual[:i] + [name]) if i > 0 else name
                if qual in self.func_index:
                    return qual
            # Check module imports
            return self.module_imports.get(name)
        elif func_node.type == "attribute":
            # Handle attribute calls like obj.method()
            object_node = func_node.child_by_field_name("object")
            attr_node = func_node.child_by_field_name("attribute")
            if object_node and attr_node:
                obj_name = self._get_text(object_node)
                attr_name = self._get_text(attr_node)

                # Handle module.function calls
                if obj_name in self.module_imports:
                    return f"{self.module_imports[obj_name]}.{attr_name}"

                # Handle self.method calls within class
                if obj_name == "self" and len(self.scope_qual) >= 2:
                    class_qual = ".".join(self.scope_qual[:-1])
                    return f"{class_qual}.{attr_name}"

        return None

    def _get_text(self, node: TSNode) -> str:
        """Get text content of a node."""
        return self.source[node.start_byte : node.end_byte]

    def _count_tokens(self, node: TSNode) -> int:
        # TODO: Replace with proper tokenizer for accurate token count
        return len(self._snippet(node).split()) // 3

    def _collect_parameter_identifiers(
        self, parameters_node: TSNode | None
    ) -> list[TSNode]:
        if not parameters_node:
            return []
        identifiers: list[TSNode] = []
        for child in parameters_node.children:
            identifiers.extend(self._iter_identifiers(child))
        seen: set[str] = set()
        ordered: list[TSNode] = []
        for ident in identifiers:
            name = self._get_text(ident)
            if name in seen:
                continue
            seen.add(name)
            ordered.append(ident)
        return ordered

    def _infer_parameter_annotation(self, ident: TSNode) -> str:
        parent = ident.parent
        while parent and parent.type == "identifier":
            parent = parent.parent
        if not parent:
            return ""
        annotation = parent.child_by_field_name("type")
        return self._get_text(annotation).strip() if annotation else ""

    def _extract_signature(self, parameters_node: TSNode | None) -> str:
        if not parameters_node:
            return "()"
        signature = self._get_text(parameters_node).strip()
        return signature if signature else "()"

    def _estimate_cyclomatic_complexity(self, body_node: TSNode | None) -> int:
        if not body_node:
            return 1
        stack = [body_node]
        complexity = 1
        while stack:
            current = stack.pop()
            if current.type in COMPLEXITY_NODES:
                complexity += 1
            stack.extend(current.children)
        return complexity

    def _has_decorators(self, node: TSNode) -> bool:
        parent = node.parent
        return bool(parent and parent.type == "decorated_definition")

    def _extract_class_bases(self, node: TSNode) -> list[str]:
        """Extract textual base class names for a class definition."""

        arguments = next(
            (child for child in node.children if child.type == "argument_list"), None
        )
        if not arguments:
            return []
        bases: list[str] = []
        for child in arguments.children:
            if child.type in {"identifier", "attribute", "dotted_name"}:
                bases.append(self._get_text(child))
        return bases

    def _iter_identifiers(self, node: TSNode) -> Iterator[TSNode]:
        if node.type == "identifier":
            yield node
        for child in node.children:
            yield from self._iter_identifiers(child)

    def _iter_assignment_targets(
        self, node: TSNode
    ) -> Iterator[tuple[str, TSNode, bool]]:
        if node.type == "identifier":
            yield self._get_text(node), node, False
            return
        if node.type == "attribute":
            attr = node.child_by_field_name("attribute")
            obj = node.child_by_field_name("object")
            if attr:
                yield (
                    self._get_text(attr),
                    attr,
                    bool(obj and self._get_text(obj) == "self"),
                )
            return
        for child in node.children:
            yield from self._iter_assignment_targets(child)

    def _register_variable(
        self,
        name: str,
        scope: VariableScope,
        line_number: int,
        type_hint: str = "",
    ) -> None:
        qualifier = self._qual(name)
        base_id = f"variable:{qualifier}@{self.file}:{line_number}"
        node_id = base_id
        counter = 1
        while node_id in self.structured_nodes:
            counter += 1
            node_id = f"{base_id}#{counter}"
        variable = VariableNode(
            name=name,
            scope=scope,
            type_hint=type_hint,
            line_number=line_number,
            file_path=self.file,
            is_user_input=self._is_user_input(name),
            is_sensitive=self._is_sensitive(name),
        )
        self.structured_nodes[node_id] = variable

    def _is_user_input(self, name: str) -> bool:
        return name.lower() in USER_INPUT_NAMES

    def _is_sensitive(self, name: str) -> bool:
        lowered = name.lower()
        return lowered in SENSITIVE_NAMES

    def _resolve_module_name(self, raw: str) -> str:
        text = (raw or "").strip()
        if not text:
            return ""
        leading = len(text) - len(text.lstrip("."))
        module = text.lstrip(".")
        if leading == 0:
            return module

        base_parts = self.module_name.split(".")[:-1]
        steps_up = max(leading - 1, 0)
        if steps_up > 0:
            base_parts = base_parts[:-steps_up] if steps_up <= len(base_parts) else []

        resolved_parts = [p for p in base_parts if p]
        if module:
            resolved_parts.append(module)
        return ".".join(resolved_parts)


class TreeSitterProjectCPGBuilder:
    """Build a CPG using tree-sitter for a multi-file project."""

    def __init__(self, root: Path, parser: Parser, ignore_magic: bool = True):
        self.root = Path(root)
        self.parser = parser
        self.ignore_magic = ignore_magic

    def _module_name_for(self, file: Path) -> str:
        """Calculate module name for a file relative to project root."""
        rel = file.relative_to(self.root)
        parts = list(rel.parts)
        if parts[-1] == "__init__.py":
            parts = parts[:-1]
        else:
            parts[-1] = parts[-1].removesuffix(".py")

        if not parts:
            return self.root.name
        return ".".join(p for p in parts if p)

    def iter_python_files(self) -> Iterable[Path]:
        """Iterate over Python files in the project."""
        for p in self.root.rglob("*.py"):
            if "__pycache__" in p.parts:
                continue
            yield p

    def build(self) -> tuple[dict[str, DeprecatedNode], list[Edge]]:
        """Build CPG for the entire project."""
        all_nodes: dict[str, DeprecatedNode] = {}
        all_edges: list[Edge] = []
        builders: list[TreeSitterCPGBuilder] = []

        # First pass: build each file graph
        for pyfile in self.iter_python_files():
            src = pyfile.read_text(encoding="utf-8")
            module_name = self._module_name_for(pyfile)

            builder = TreeSitterCPGBuilder(
                src,
                str(pyfile),
                self.parser,
                ignore_magic=self.ignore_magic,
                module_name=module_name,
            )
            nodes, edges = builder.build()
            all_nodes.update(nodes)
            all_edges.extend(edges)
            builders.append(builder)

        # Global function index for cross-file resolution
        global_func_index: dict[str, str] = {}
        for b in builders:
            global_func_index.update(b.func_index)

        # Second pass: resolve cross-file calls
        for b in builders:
            for src_id, qual in b.pending_calls:
                dst_id = global_func_index.get(qual)
                if dst_id:
                    all_edges.append(Edge(src=src_id, dst=dst_id, type=EdgeType.CALLS))

        return all_nodes, all_edges

    def build_structured(self) -> tuple[dict[str, Node], list[Edge]]:
        """Build structured nodes for the entire project."""

        structured_nodes: dict[str, Node] = {}
        all_edges: list[Edge] = []
        builders: list[TreeSitterCPGBuilder] = []

        for pyfile in self.iter_python_files():
            src = pyfile.read_text()
            module_name = self._module_name_for(pyfile)
            builder = TreeSitterCPGBuilder(
                src,
                str(pyfile),
                self.parser,
                ignore_magic=self.ignore_magic,
                module_name=module_name,
            )
            nodes, edges = builder.build_structured()
            structured_nodes.update(nodes)
            all_edges.extend(edges)
            builders.append(builder)

        global_func_index: dict[str, str] = {}
        for b in builders:
            global_func_index.update(b.func_index)

        for b in builders:
            for src_id, qual in b.pending_calls:
                dst_id = global_func_index.get(qual)
                if dst_id:
                    all_edges.append(Edge(src=src_id, dst=dst_id, type=EdgeType.CALLS))

        return structured_nodes, all_edges
