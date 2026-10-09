import ast
import logging
import os
import warnings
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import tree_sitter_python as tspython
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr
from tree_sitter import Language, Parser, Tree

from models.base import NodeID
from models.edges.base import RelationshipBase
from models.nodes import Node, VariableNode
from models.nodes.code import ClassNode, FunctionNode
from services.cpg_parser.ts_parser.field_links import (
    FieldAccess,
    FieldDeclaration,
    link_field_accesses,
)
from services.cpg_parser.ts_parser.node_processor import NodeProcessor
from services.cpg_parser.ts_parser.project_symbols import ProjectSymbols
from services.cpg_parser.types import ParserResult

_LOGGER = logging.getLogger(__name__)


class CPGFileBuilder(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    path: Path
    root: Path | None = None
    prebound_symbols: dict[str, NodeID] = Field(default_factory=dict)
    prebound_modules: dict[str, dict[str, NodeID]] = Field(default_factory=dict)
    project_symbols: ProjectSymbols = Field(default_factory=ProjectSymbols)
    __parser: Parser = PrivateAttr(default_factory=lambda: Parser(Language(tspython.language())))
    __tree: Tree = PrivateAttr()
    __source: bytes = PrivateAttr()
    __source_text: str = PrivateAttr()
    __lines: list[str] = PrivateAttr()
    __processor: NodeProcessor = PrivateAttr()
    __display_path: Path = PrivateAttr()

    def model_post_init(self, context: Any) -> None:
        absolute_path: Path = self.path.resolve()
        self.__display_path = self._display_path_for(self.path, absolute_path)
        self.__source = absolute_path.read_bytes()
        self.__source_text = self.__source.decode("utf-8", errors="replace")
        self.__tree = self.__parser.parse(self.__source)
        # Split on "\n" only: tree-sitter rows ignore the extra separators
        # ``str.splitlines`` honours (form feed, \x1c-\x1e, \x85,  , ...).
        self.__lines = [line.removesuffix("\r") for line in self.__source_text.split("\n")]
        self.__processor = NodeProcessor(
            path=self.__display_path,
            source=self.__source,
            source_text=self.__source_text,
            lines=self.__lines,
            prebound_symbols=self.prebound_symbols,
            prebound_modules=self.prebound_modules,
            project_symbols=self.project_symbols,
        )
        return super().model_post_init(context)

    def _display_path_for(self, raw_path: Path, absolute_path: Path) -> Path:
        """Normalize file paths relative to the project root.

        Args:
            raw_path: Original path provided to the builder.
            absolute_path: Absolute file system path for the source file.

        Returns:
            Path to store in nodes and identifiers.
        """

        if self.root is None:
            if not raw_path.is_absolute():
                return Path(raw_path.as_posix())
            return absolute_path

        root_path: Path = self.root.resolve()
        try:
            relative_path: Path = absolute_path.relative_to(root_path)
            return Path(relative_path.as_posix())
        except ValueError:
            rel_str: str = os.path.relpath(absolute_path.as_posix(), root_path.as_posix())
            return Path(rel_str)

    def build(self) -> ParserResult:
        """Build a CPG representation from the file."""

        return self.__processor.process(self.__tree.root_node)

    @property
    def field_declarations(self) -> list[FieldDeclaration]:
        """Class fields declared in this file; populated by ``build``."""
        return self.__processor.field_declarations

    @property
    def field_accesses(self) -> list[FieldAccess]:
        """Attribute reads and writes in this file; populated by ``build``."""
        return self.__processor.field_accesses


@dataclass(frozen=True)
class _ClassMembers:
    methods: dict[str, int]
    bases: tuple[str, ...]


@dataclass(frozen=True)
class _ExportedNames:
    functions: dict[str, int]
    classes: dict[str, int]
    variables: dict[str, int]
    class_members: dict[str, _ClassMembers] = field(default_factory=dict)


@dataclass(frozen=True)
class _ClassRecord:
    class_id: NodeID
    file_path: Path
    module_symbols: dict[str, NodeID]
    method_ids: dict[str, NodeID]
    bases: tuple[str, ...]


@dataclass(frozen=True)
class _ModuleIndex:
    """Exported symbols of project modules, addressable by import name.

    Attributes:
        exact: Symbols by module name relative to the scanned root.
        aliases: Symbols by module name relative to the module's own source
            root (``src/pkg/mod.py`` as ``pkg.mod``), kept only when a single
            module claims the name.
    """

    exact: dict[str, dict[str, NodeID]]
    aliases: dict[str, dict[str, NodeID]]

    def lookup(
        self, module_name: str, *, source_root: str, relative: bool
    ) -> dict[str, NodeID] | None:
        """Return the symbols of the module an import statement names.

        An absolute import prefers a module under the importing file's own
        source root, then the scanned root, then an unambiguous alias.

        Args:
            module_name: Imported module; root-relative for a relative import.
            source_root: Dotted root-relative source root of the importing file.
            relative: Whether ``module_name`` was resolved from a relative import.

        Returns:
            The module's exported symbols, or ``None`` when it is not a project module.
        """

        if relative:
            return self.exact.get(module_name)
        if source_root:
            sibling = self.exact.get(f"{source_root}.{module_name}")
            if sibling is not None:
                return sibling
        exact = self.exact.get(module_name)
        if exact is not None:
            return exact
        return self.aliases.get(module_name)


@dataclass(frozen=True)
class _FileLinks:
    symbols: dict[str, NodeID]
    modules: dict[str, dict[str, NodeID]]


def _parse_module_ast(file_path: Path) -> ast.Module | None:
    """Parse ``file_path`` with ``ast``; return ``None`` when it is unreadable or not valid Python.

    The source is parsed as bytes so ``ast`` honours a UTF-8 BOM and PEP 263
    encoding declarations.
    """

    try:
        source = file_path.read_bytes()
    except OSError:
        return None
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            return ast.parse(source, filename=str(file_path))
    except (SyntaxError, ValueError):
        return None


class CPGDirectoryBuilder(BaseModel):
    """Build a CPG representation from all Python files under a directory.

    Note:
        This currently parses files independently and merges results.
        Cross-module linking (e.g., resolving calls across files) is intentionally
        not implemented yet.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    root: Path
    recursive: bool = True
    follow_symlinks: bool = False
    exclude_dir_names: set[str] = Field(
        default_factory=lambda: {
            "__pycache__",
            ".git",
            ".venv",
            "venv",
            ".mypy_cache",
            ".pytest_cache",
            "tests",
            "test",
        }
    )
    on_error: Literal["raise", "skip"] = "raise"
    link_imports: bool = True

    def build(self) -> ParserResult:
        """Build a merged CPG representation from all discovered Python files.

        Returns:
            A merged `ParserResult` containing nodes and relationships from all
            parsed files.

        Raises:
            ValueError: If `root` does not exist, is not a directory, or if node ID
                collisions are detected.
            Exception: Re-raises any parse error if `on_error="raise"`.
        """
        _LOGGER.info("Start building CPG for directory: %s", self.root)

        python_files = self._collect_python_files()

        module_by_file = {path: self._module_name_for_path(path) for path in python_files}

        links_by_file: dict[Path, _FileLinks] = {}
        project_symbols = ProjectSymbols()
        if self.link_imports:
            module_index, class_records = self._build_symbol_index(
                python_files=python_files,
                module_by_file=module_by_file,
            )
            links_by_file = {
                file_path: _FileLinks(
                    symbols=self._prebound_symbols_for_file(
                        file_path=file_path,
                        module_by_file=module_by_file,
                        module_index=module_index,
                    ),
                    modules=self._prebound_modules_for_file(
                        file_path=file_path,
                        module_by_file=module_by_file,
                        module_index=module_index,
                    ),
                )
                for file_path in python_files
            }
            project_symbols = self._build_project_symbols(
                class_records=class_records,
                links_by_file=links_by_file,
            )

        merged_nodes: dict[NodeID, Node] = {}
        merged_edges: list[RelationshipBase] = []
        field_declarations: list[FieldDeclaration] = []
        field_accesses: list[FieldAccess] = []

        for file_path in python_files:
            links = links_by_file.get(file_path, _FileLinks(symbols={}, modules={}))
            try:
                file_builder = CPGFileBuilder(
                    path=file_path,
                    root=self.root,
                    prebound_symbols=links.symbols,
                    prebound_modules=links.modules,
                    project_symbols=project_symbols,
                )
                nodes, edges = file_builder.build()
            except Exception:
                if self.on_error == "raise":
                    raise
                _LOGGER.exception("Failed to parse Python file: %s", file_path)
                continue

            for node_id, node in nodes.items():
                existing = merged_nodes.get(node_id)
                if existing is not None and existing != node:
                    raise ValueError(
                        f"Duplicate node id {node_id!s} encountered while parsing {file_path}"
                    )
                merged_nodes[node_id] = node

            merged_edges.extend(edges)
            field_declarations.extend(file_builder.field_declarations)
            field_accesses.extend(file_builder.field_accesses)

        field_edges = [
            edge
            for edge in link_field_accesses(
                field_declarations, field_accesses, project_symbols.class_bases
            )
            if edge.src in merged_nodes and edge.dst in merged_nodes
        ]
        merged_edges.extend(field_edges)
        _LOGGER.info("Linked %d field accesses to declared fields", len(field_edges))

        _LOGGER.info(
            "Finished building CPG for directory: %s. Parsed %d files with %d nodes and %d edges.",
            self.root,
            len(python_files),
            len(merged_nodes),
            len(merged_edges),
        )

        return merged_nodes, merged_edges

    def _module_name_for_path(self, file_path: Path, base: Path | None = None) -> str:
        rel = file_path.relative_to(base or self.root)
        rel = rel.parent if rel.name == "__init__.py" else rel.with_suffix("")
        parts = list(rel.parts)
        return ".".join(parts)

    def _source_root_for_path(self, file_path: Path) -> Path:
        """Return the source root of ``file_path``: its first ancestor without ``__init__.py``."""

        source_root = file_path.parent
        while source_root != self.root and (source_root / "__init__.py").is_file():
            source_root = source_root.parent
        return source_root

    def _source_root_name_for_path(self, file_path: Path) -> str:
        """Return the dotted root-relative name of the source root of ``file_path``."""

        return ".".join(self._source_root_for_path(file_path).relative_to(self.root).parts)

    def _package_module_name_for_path(self, file_path: Path) -> str:
        """Return the import name of ``file_path`` relative to its source root.

        ``src/pkg/mod.py`` (with ``src/pkg/__init__.py``) is ``pkg.mod``.
        """

        return self._module_name_for_path(file_path, base=self._source_root_for_path(file_path))

    def _parse_exported_names(self, file_path: Path) -> _ExportedNames:
        tree = _parse_module_ast(file_path)
        if tree is None:
            return _ExportedNames(functions={}, classes={}, variables={})

        functions: dict[str, int] = {}
        classes: dict[str, int] = {}
        variables: dict[str, int] = {}
        class_members: dict[str, _ClassMembers] = {}

        for stmt in tree.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions[stmt.name] = stmt.lineno
                continue
            if isinstance(stmt, ast.ClassDef):
                classes[stmt.name] = stmt.lineno
                class_members[stmt.name] = _ClassMembers(
                    methods={
                        member.name: member.lineno
                        for member in stmt.body
                        if isinstance(member, ast.FunctionDef | ast.AsyncFunctionDef)
                    },
                    bases=tuple(ast.unparse(base) for base in stmt.bases),
                )
                continue
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        variables[target.id] = target.lineno
                continue
            if isinstance(stmt, ast.AnnAssign):
                target = stmt.target
                if isinstance(target, ast.Name):
                    variables[target.id] = target.lineno
                continue

        return _ExportedNames(
            functions=functions,
            classes=classes,
            variables=variables,
            class_members=class_members,
        )

    def _build_symbol_index(
        self,
        *,
        python_files: list[Path],
        module_by_file: dict[Path, str],
    ) -> tuple[_ModuleIndex, list[_ClassRecord]]:
        """Index exported module symbols and class members across the project.

        Returns:
            Exported symbols per module name, and one record per top-level class
            with its method identifiers and unresolved base expressions.
        """

        exact: dict[str, dict[str, NodeID]] = {}
        alias_claims: dict[str, list[dict[str, NodeID]]] = defaultdict(list)
        class_records: list[_ClassRecord] = []

        for file_path in python_files:
            module_name = module_by_file[file_path]
            exported = self._parse_exported_names(file_path=file_path)

            try:
                nodes, _edges = CPGFileBuilder(
                    path=file_path,
                    root=self.root,
                    prebound_symbols={},
                ).build()
            except Exception:
                if self.on_error == "raise":
                    raise
                _LOGGER.exception("Failed to parse Python file (symbol index): %s", file_path)
                continue

            module_symbols = self._module_symbols_for_file(exported=exported, nodes=nodes)

            exact.setdefault(module_name, module_symbols)
            alias = self._package_module_name_for_path(file_path)
            if alias != module_name:
                alias_claims[alias].append(module_symbols)

            class_records.extend(
                self._class_records_for_file(
                    file_path=file_path,
                    exported=exported,
                    module_symbols=module_symbols,
                    nodes=nodes,
                )
            )

        aliases: dict[str, dict[str, NodeID]] = {
            alias: claims[0] for alias, claims in alias_claims.items() if len(claims) == 1
        }
        return _ModuleIndex(exact=exact, aliases=aliases), class_records

    def _module_symbols_for_file(
        self,
        *,
        exported: _ExportedNames,
        nodes: dict[NodeID, Node],
    ) -> dict[str, NodeID]:
        """Match exported names to node identifiers by kind, name and definition line."""

        function_ids: dict[tuple[str, int], NodeID] = {}
        class_ids: dict[tuple[str, int], NodeID] = {}
        variable_ids: dict[tuple[str, int], NodeID] = {}
        for node_id, node in nodes.items():
            if isinstance(node, FunctionNode):
                function_ids.setdefault((node.name, node.line_start), node_id)
            elif isinstance(node, ClassNode):
                class_ids.setdefault((node.name, node.line_start), node_id)
            elif isinstance(node, VariableNode):
                variable_ids.setdefault((node.name, node.line_start), node_id)

        module_symbols: dict[str, NodeID] = {}
        for exported_names, node_ids in (
            (exported.functions, function_ids),
            (exported.classes, class_ids),
            (exported.variables, variable_ids),
        ):
            module_symbols.update(
                {
                    name: node_ids[(name, lineno)]
                    for name, lineno in exported_names.items()
                    if (name, lineno) in node_ids
                }
            )
        return module_symbols

    def _class_records_for_file(
        self,
        *,
        file_path: Path,
        exported: _ExportedNames,
        module_symbols: dict[str, NodeID],
        nodes: dict[NodeID, Node],
    ) -> list[_ClassRecord]:
        method_ids_by_name_line: dict[tuple[str, int], NodeID] = {
            (node.name, node.line_start): node_id
            for node_id, node in nodes.items()
            if isinstance(node, FunctionNode)
        }
        return [
            _ClassRecord(
                class_id=module_symbols[class_name],
                file_path=file_path,
                module_symbols=module_symbols,
                method_ids={
                    method_name: method_ids_by_name_line[(method_name, lineno)]
                    for method_name, lineno in members.methods.items()
                    if (method_name, lineno) in method_ids_by_name_line
                },
                bases=members.bases,
            )
            for class_name, members in exported.class_members.items()
            if class_name in module_symbols
        ]

    def _prebound_modules_for_file(
        self,
        *,
        file_path: Path,
        module_by_file: dict[Path, str],
        module_index: _ModuleIndex,
    ) -> dict[str, dict[str, NodeID]]:
        """Map module-alias receivers (``h`` in ``h.f()``) to that module's symbols.

        Covers ``import a.b``, ``import a.b as h`` and ``from a import b`` when
        ``a.b`` is a project module.
        """

        tree = _parse_module_ast(file_path)
        if tree is None:
            return {}

        current_module = module_by_file[file_path]
        source_root = self._source_root_name_for_path(file_path)
        modules: dict[str, dict[str, NodeID]] = {}
        for stmt in tree.body:
            if isinstance(stmt, ast.Import):
                for alias in stmt.names:
                    module_symbols = module_index.lookup(
                        alias.name, source_root=source_root, relative=False
                    )
                    if module_symbols is not None:
                        modules[alias.asname or alias.name] = module_symbols
                continue
            if not isinstance(stmt, ast.ImportFrom):
                continue
            package = self._resolve_import_from_module(
                current_module=current_module,
                is_package=file_path.name == "__init__.py",
                level=stmt.level,
                module=stmt.module,
            )
            if package is None:
                continue
            for alias in stmt.names:
                submodule = f"{package}.{alias.name}" if package else alias.name
                module_symbols = module_index.lookup(
                    submodule, source_root=source_root, relative=stmt.level > 0
                )
                if module_symbols is not None:
                    modules[alias.asname or alias.name] = module_symbols
        return modules

    def _build_project_symbols(
        self,
        *,
        class_records: list[_ClassRecord],
        links_by_file: dict[Path, _FileLinks],
    ) -> ProjectSymbols:
        """Resolve class bases and collect repository-unique method names."""

        class_bases: dict[NodeID, tuple[NodeID, ...]] = {
            record.class_id: tuple(
                base_id
                for base in record.bases
                if (
                    base_id := self._resolve_base_class(
                        base,
                        module_symbols=record.module_symbols,
                        links=links_by_file.get(record.file_path, _FileLinks({}, {})),
                    )
                )
                is not None
            )
            for record in class_records
        }

        name_counts: Counter[str] = Counter(
            name for record in class_records for name in record.method_ids
        )
        unique_methods: dict[str, NodeID] = {
            name: method_id
            for record in class_records
            for name, method_id in record.method_ids.items()
            if name_counts[name] == 1 and not (name.startswith("__") and name.endswith("__"))
        }

        return ProjectSymbols(
            class_methods={record.class_id: record.method_ids for record in class_records},
            class_bases=class_bases,
            unique_methods=unique_methods,
        )

    def _resolve_base_class(
        self,
        base: str,
        *,
        module_symbols: dict[str, NodeID],
        links: _FileLinks,
    ) -> NodeID | None:
        receiver, _, name = base.rpartition(".")
        if receiver:
            candidate = links.modules.get(receiver, {}).get(name)
        else:
            candidate = module_symbols.get(name) or links.symbols.get(name)
        if candidate is None or not str(candidate).startswith("class:"):
            return None
        return candidate

    def _prebound_symbols_for_file(
        self,
        *,
        file_path: Path,
        module_by_file: dict[Path, str],
        module_index: _ModuleIndex,
    ) -> dict[str, NodeID]:
        tree = _parse_module_ast(file_path)
        if tree is None:
            return {}

        current_module = module_by_file[file_path]
        source_root = self._source_root_name_for_path(file_path)
        prebound: dict[str, NodeID] = {}

        for stmt in tree.body:
            if not isinstance(stmt, ast.ImportFrom):
                continue

            resolved_module = self._resolve_import_from_module(
                current_module=current_module,
                is_package=file_path.name == "__init__.py",
                level=stmt.level,
                module=stmt.module,
            )
            if resolved_module is None:
                continue

            module_symbols = module_index.lookup(
                resolved_module, source_root=source_root, relative=stmt.level > 0
            )
            if module_symbols is None:
                continue

            for alias in stmt.names:
                if alias.name == "*":
                    continue
                local_name = alias.asname or alias.name
                target_id = module_symbols.get(alias.name)
                if target_id is not None:
                    prebound[local_name] = target_id

        return prebound

    def _resolve_import_from_module(
        self,
        *,
        current_module: str,
        is_package: bool,
        level: int,
        module: str | None,
    ) -> str | None:
        if level < 0:
            return None

        # A package's ``__init__`` is its own current package for relative imports.
        if is_package:
            current_package = current_module
        else:
            current_package = current_module.rsplit(".", 1)[0] if "." in current_module else ""

        # level=0 => absolute import
        if level == 0:
            return module

        # level=1 => current package; level=2 => parent of current package, etc.
        # Climbing above the scanned root targets a module outside the project.
        parts = [p for p in current_package.split(".") if p]
        up = level - 1
        if up > len(parts):
            return None
        if up:
            parts = parts[:-up]

        if module:
            parts.extend([p for p in module.split(".") if p])

        return ".".join(parts) if parts else (module or "")

    def _collect_python_files(self) -> list[Path]:
        if not self.root.exists():
            raise ValueError(f"Root path does not exist: {self.root}")
        if not self.root.is_dir():
            raise ValueError(f"Root path must be a directory: {self.root}")

        files: list[Path] = []

        if self.recursive:
            for dirpath, dirnames, filenames in os.walk(
                self.root, followlinks=self.follow_symlinks
            ):
                dirnames[:] = [name for name in dirnames if name not in self.exclude_dir_names]
                for filename in filenames:
                    if not filename.endswith(".py"):
                        continue
                    candidate = Path(dirpath) / filename
                    if candidate.is_file():
                        files.append(candidate)
        else:
            for candidate in self.root.iterdir():
                if candidate.is_file() and candidate.name.endswith(".py"):
                    files.append(candidate)

        # Deterministic order for stable builds/tests.
        return sorted(files)
