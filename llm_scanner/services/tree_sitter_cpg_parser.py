from pathlib import Path
from typing import Iterable, Optional, Any

import tree_sitter_python as tspython
from tree_sitter import Language, Parser, Node as TSNode


from models.edge import Edge, EdgeType
from models.node import Node, NodeType
from services.cpg_parser_interface import CPGParserProtocol


class TreeSitterCPGParser:
    """CPG parser implementation using py-tree-sitter."""

    def __init__(self):
        self.language = Language(tspython.language())
        self.parser = Parser(self.language)

    def parse_file(
        self, path: Path, ignore_magic: bool = True
    ) -> tuple[dict[str, Node], list[Edge]]:
        """Parse a single file using tree-sitter into a CPG.

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
            return builder.build()
        except Exception as e:
            raise ValueError(f"Failed to parse file {path}: {e}") from e

    def parse_project(
        self, root: Path, ignore_magic: bool = True
    ) -> tuple[dict[str, Node], list[Edge]]:
        """Parse a project directory using tree-sitter into a CPG.

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
            return builder.build()
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

        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self.pending_calls: list[tuple[str, str]] = []

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

    def generate_id(self, type_: NodeType, name: str, file: str, lineno: int) -> str:
        """Generate a unique node ID.

        Args:
            type_: The node type enum value
            name: The node name
            file: The file path
            lineno: The line number

        Returns:
            Unique node identifier string
        """
        return f"{type_.value.lower()}:{name}@{file}:{lineno}"

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
        n = Node(
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

    def _current(self) -> Optional[Node]:
        return self.nodes.get(self.current_stack[-1]) if self.current_stack else None

    def _qual(self, name: str) -> str:
        if self.scope_qual:
            return ".".join(self.scope_qual + [name])
        return name

    def _check_if_magic(self, name: str) -> bool:
        return self.ignore_magic and name.startswith("__") and name.endswith("__")

    def build(self) -> tuple[dict[str, Node], list[Edge]]:
        """Build CPG from the parsed tree.

        Returns:
            Tuple of (nodes_dict, edges_list) representing the CPG
        """
        root = self.tree.root_node

        # Create module node
        mod_id = self._new_node(
            NodeType.MODULE, self.module_name.split(".")[-1], self.module_name, root
        )
        self._push(mod_id, self.module_name)

        # Process all nodes
        self._process_node(root)

        self._pop()
        return self.nodes, self.edges

    def _process_node(self, node: TSNode):
        """Process a tree-sitter node and its children."""
        if node.type == "function_definition":
            self._process_function(node)
        elif node.type == "class_definition":
            self._process_class(node)
        elif node.type == "import_statement":
            self._process_import(node)
        elif node.type == "import_from_statement":
            self._process_import_from(node)
        elif node.type == "call":
            self._process_call(node)
        else:
            # Process children recursively
            for child in node.children:
                self._process_node(child)

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

        # Add contains edge
        if self.current_stack:
            self.edges.append(
                Edge(src=self.current_stack[-1], dst=node_id, type=EdgeType.CONTAINS)
            )

        # Collect function parameters
        cur = self.nodes[node_id]
        parameters_node = node.child_by_field_name("parameters")
        if parameters_node:
            for param_node in parameters_node.children:
                if param_node.type == "identifier":
                    cur.locals.add(self._get_text(param_node))

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

        # Add contains edge
        if self.current_stack:
            self.edges.append(
                Edge(src=self.current_stack[-1], dst=node_id, type=EdgeType.CONTAINS)
            )

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
            elif child.type == "aliased_import":
                name_node = child.child_by_field_name("name")
                alias_node = child.child_by_field_name("alias")
                if name_node and alias_node:
                    module_name = self._get_text(name_node)
                    alias = self._get_text(alias_node)
                    cur.imports.add(alias)
                    if cur.type == NodeType.MODULE:
                        self.module_imports[alias] = module_name

    def _process_import_from(self, node: TSNode):
        """Process a from...import statement."""
        cur = self._current()
        if not cur:
            return

        module_node = node.child_by_field_name("module_name")
        module_name = self._get_text(module_node) if module_node else ""

        # Find imported names
        for child in node.children:
            if child.type == "import_list":
                for import_child in child.children:
                    if import_child.type == "dotted_name":
                        name = self._get_text(import_child)
                        full_name = f"{module_name}.{name}" if module_name else name
                        cur.imports.add(full_name)
                        if cur.type == NodeType.MODULE:
                            self.module_imports[name] = full_name
                    elif import_child.type == "aliased_import":
                        name_node = import_child.child_by_field_name("name")
                        alias_node = import_child.child_by_field_name("alias")
                        if name_node and alias_node:
                            name = self._get_text(name_node)
                            alias = self._get_text(alias_node)
                            full_name = f"{module_name}.{name}" if module_name else name
                            cur.imports.add(full_name)
                            if cur.type == NodeType.MODULE:
                                self.module_imports[alias] = full_name

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

    def _collect_symbols(self, node: TSNode, cur: Node):
        """Collect symbols (locals, globals, imports, calls) from node tree."""
        if node.type == "assignment":
            # Collect assigned variables
            for target in node.children:
                if target.type == "identifier":
                    cur.locals.add(self._get_text(target))
        elif node.type == "global_statement":
            # Collect global declarations
            for child in node.children:
                if child.type == "identifier":
                    cur.globals.add(self._get_text(child))
        elif node.type == "call":
            self._process_call(node)
        elif node.type in ("import_statement", "import_from_statement"):
            if node.type == "import_statement":
                self._process_import(node)
            else:
                self._process_import_from(node)

        # Recursively process children
        for child in node.children:
            self._collect_symbols(child, cur)

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

    def build(self) -> tuple[dict[str, Node], list[Edge]]:
        """Build CPG for the entire project."""
        all_nodes: dict[str, Node] = {}
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
