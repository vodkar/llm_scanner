import ast
from functools import singledispatchmethod
from pathlib import Path
from typing import Optional, Iterable

from models.edge import Edge, EdgeType
from models.node import Node, NodeType


# ------------- Parser -----------------


class CPGBuilder(ast.NodeVisitor):
    """Build a lightweight code property graph (functions/classes only).

    - Nodes: Module, ClassDef, FunctionDef/AsyncFunctionDef
    - Edges:
        * CONTAINS: module->class/function, class->method
        * DEFINES: class/function -> local/global/import symbols
        * CALLS: function/method -> function/method
    - Node props: code snippet, imports used, local and global variables used

    Limits:
    - Best-effort resolve calls by name within same module and class scope
    - No external libs resolution; magic methods ignored if desired by filter
    - Simple variable collection (Assign, AnnAssign, AugAssign, arguments)
    """

    def __init__(self, source: str, file: str, ignore_magic: bool = True) -> None:
        self.source = source
        self.file = file
        self.module = ast.parse(source)
        self.ignore_magic = ignore_magic

        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []

        # symbol tables for resolution within module
        self.current_stack: list[str] = []  # list of node ids
        self.scope_qual: list[str] = []  # list of name parts for qualname
        self.func_index: dict[str, str] = {}  # qualname -> node_id
        self.class_index: dict[str, str] = {}
        self.module_imports: dict[str, str] = (
            {}
        )  # bound name -> module or module.symbol

        # helper: map ast node to its code
        self._lines = source.splitlines()

    # ------------ utilities -------------

    def _snippet(self, node: ast.AST) -> str:
        # Use lineno/end_lineno (1-based, inclusive)
        start = getattr(node, "lineno", 1)
        end = getattr(node, "end_lineno", start)
        return "\n".join(self._lines[start - 1 : end])

    def _new_node(
        self, type_: NodeType, name: str, qualname: str, node: ast.AST
    ) -> str:
        node_id = f"{type_.lower()}:{qualname}@{self.file}:{getattr(node,'lineno',0)}"
        n = Node(
            id=node_id,
            type=type_,
            name=name,
            qualname=qualname,
            file=self.file,
            lineno=getattr(node, "lineno", 0),
            end_lineno=getattr(node, "end_lineno", getattr(node, "lineno", 0)),
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

    def __check_if_magic(self, name: str) -> bool:
        return self.ignore_magic and name.startswith("__") and name.endswith("__")

    # ------------ visit -------------

    def build(self) -> tuple[dict[str, Node], list[Edge]]:
        # module node
        mod_id = self._new_node(
            NodeType.MODULE, Path(self.file).stem, Path(self.file).stem, self.module
        )
        self._push(mod_id, Path(self.file).stem)
        self.generic_visit(self.module)
        self._pop()
        return self.nodes, self.edges

    def visit_Import(self, node: ast.Import) -> None:
        # record import symbols for current node (module/function/class)
        for alias in node.names:
            name = alias.asname or alias.name
            cur = self._current()
            if cur:
                cur.imports.add(name)
            # record module-scope bindings for later reference attribution
            if cur and cur.type == NodeType.MODULE:
                # For `import pkg.sub as x`, name is alias (x), value stored as alias.name
                self.module_imports[name.split(".")[0]] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            name = alias.asname or alias.name
            cur = self._current()
            if cur:
                mod = node.module or ""
                cur.imports.add(f"{mod}.{name}" if mod else name)
            if cur and cur.type == NodeType.MODULE:
                mod = node.module or ""
                bound = name
                value = f"{mod}.{alias.name}" if mod else alias.name
                self.module_imports[bound] = value
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        if self.__check_if_magic(node.name):
            return
        qual = self._qual(node.name)
        node_id = self._new_node(NodeType.CLASS, node.name, qual, node)
        self.class_index[qual] = node_id
        # contains edge
        if self.current_stack:
            self.edges.append(
                Edge(src=self.current_stack[-1], dst=node_id, type=EdgeType.CONTAINS)
            )
        self._push(node_id, node.name)
        self.generic_visit(node)
        self._pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if self.__check_if_magic(node.name):
            return
        self._handle_functionlike(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        if self.__check_if_magic(node.name):
            return
        self._handle_functionlike(node)

    def _handle_functionlike(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        name: str = node.name  # type: ignore[attr-defined]
        qual = self._qual(name)
        node_id = self._new_node(NodeType.FUNCTION, name, qual, node)
        self.func_index[qual] = node_id
        if self.current_stack:
            self.edges.append(
                Edge(src=self.current_stack[-1], dst=node_id, type=EdgeType.CONTAINS)
            )
        # collect args as locals
        cur = self.nodes[node_id]
        args: list[str] = []
        fnargs = node.args  # type: ignore[attr-defined]
        for a in list(fnargs.posonlyargs) + list(fnargs.args) + list(fnargs.kwonlyargs):
            args.append(a.arg)
        if fnargs.vararg:
            args.append(fnargs.vararg.arg)
        if fnargs.kwarg:
            args.append(fnargs.kwarg.arg)
        cur.locals.update(args)

        # walk body to collect locals, globals, imports, and calls
        self._push(node_id, name)
        for stmt in node.body:  # type: ignore[attr-defined]
            self._scan_stmt(stmt, cur)
        self._pop()

    # ---------- scanners ----------

    def _scan_stmt(self, node: ast.stmt, cur: Node) -> None:
        for child in ast.walk(node):
            self._process_stmt(child, cur)

    @singledispatchmethod
    def _process_stmt(self, stmt: ast.stmt, cur: Node) -> None:
        if isinstance(stmt, ast.Name) and isinstance(stmt.ctx, ast.Load):
            # attribute module import usage to this function/method
            nm = stmt.id
            if nm in self.module_imports and nm not in cur.locals:
                cur.imports.add(self.module_imports[nm])

    @_process_stmt.register
    def _process_assignment(
        self, stmt: ast.Assign | ast.AnnAssign | ast.AugAssign, cur: Node
    ) -> None:
        targets: Iterable[ast.AST]
        if isinstance(stmt, ast.Assign):
            targets = stmt.targets
        else:
            targets = [stmt.target]
        for t in targets:
            for name in self._extract_target_names(t):
                cur.locals.add(name)

    @_process_stmt.register
    def _process_global(self, stmt: ast.Global, cur: Node) -> None:
        for name in stmt.names:
            cur.globals.add(name)

    @_process_stmt.register
    def _process_import(self, stmt: ast.Import | ast.ImportFrom, cur: Node) -> None:
        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                n = alias.asname or alias.name
                cur.imports.add(n)
        else:
            mod = stmt.module or ""
            for alias in stmt.names:
                n = alias.asname or alias.name
                cur.imports.add(f"{mod}.{n}" if mod else n)

    @_process_stmt.register
    def _process_call(self, stmt: ast.Call, cur: Node) -> None:
        callee = self._resolve_call(stmt.func)
        if callee:
            # create CALLS edge if known
            if callee in self.func_index:
                self.edges.append(
                    Edge(src=cur.id, dst=self.func_index[callee], type=EdgeType.CALLS)
                )

    def _extract_target_names(self, t: ast.AST) -> Iterable[str]:
        if isinstance(t, ast.Name):
            return [t.id]
        if isinstance(t, (ast.Tuple, ast.List)):
            names: list[str] = []
            for elt in t.elts:  # type: ignore[attr-defined]
                names.extend(self._extract_target_names(elt))
            return names
        return []

    @singledispatchmethod
    def _resolve_call(self, _func: ast.AST) -> str | None:
        return None  # default case, unsupported type

    @_resolve_call.register
    def _resolve_call_name(self, func: ast.Name) -> str | None:
        # Best-effort: Name -> qual within scope; Attribute -> maybe method/qualified
        # try scoped function name
        name = func.id
        # search from inner to outer scope
        for i in range(len(self.scope_qual), -1, -1):
            qual = ".".join(self.scope_qual[:i] + [name]) if i > 0 else name
            if qual in self.func_index:
                return qual
        return None

    @_resolve_call.register
    def _resolve_call_attr(self, func: ast.Attribute) -> str | None:
        # attr of object; if object is 'self' and we're inside a class, resolve method
        # current class is scope_qual[-2] when inside a function in class
        if len(self.scope_qual) >= 2:
            class_qual = ".".join(self.scope_qual[:-1])
            qual = f"{class_qual}.{func.attr}"
            return qual if qual in self.func_index else None
        # Fallback: module-level attr call won't be resolved (external)
        return None
