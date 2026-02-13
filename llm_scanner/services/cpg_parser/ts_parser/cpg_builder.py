import ast
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import tree_sitter_python as tspython
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr
from tree_sitter import Language, Parser, Tree

from models.base import NodeID
from models.edges.base import RelationshipBase
from models.nodes import Node
from services.cpg_parser.ts_parser.node_processor import NodeProcessor
from services.cpg_parser.types import ParserResult

logger = logging.getLogger(__name__)


class CPGFileBuilder(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    path: Path
    root: Path | None = None
    prebound_symbols: dict[str, NodeID] = Field(default_factory=dict)
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
        self.__source_text = self.__source.decode("utf-8")
        self.__tree = self.__parser.parse(self.__source)
        self.__lines = self.__source_text.splitlines()
        self.__processor = NodeProcessor(
            path=self.__display_path,
            source=self.__source,
            source_text=self.__source_text,
            lines=self.__lines,
            prebound_symbols=self.prebound_symbols,
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


@dataclass(frozen=True)
class _ExportedNames:
    functions: dict[str, int]
    classes: dict[str, int]
    variables: dict[str, int]


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

        python_files = self._collect_python_files()

        module_by_file = {path: self._module_name_for_path(path) for path in python_files}

        symbol_index: dict[str, dict[str, NodeID]] = {}
        if self.link_imports:
            symbol_index = self._build_symbol_index(
                python_files=python_files,
                module_by_file=module_by_file,
            )

        merged_nodes: dict[NodeID, Node] = {}
        merged_edges: list[RelationshipBase] = []

        for file_path in python_files:
            try:
                prebound: dict[str, NodeID] = {}
                if self.link_imports:
                    prebound = self._prebound_symbols_for_file(
                        file_path=file_path,
                        module_by_file=module_by_file,
                        symbol_index=symbol_index,
                    )
                nodes, edges = CPGFileBuilder(
                    path=file_path,
                    root=self.root,
                    prebound_symbols=prebound,
                ).build()
            except Exception:
                if self.on_error == "raise":
                    raise
                logger.exception("Failed to parse Python file: %s", file_path)
                continue

            for node_id, node in nodes.items():
                existing = merged_nodes.get(node_id)
                if existing is not None and existing != node:
                    raise ValueError(
                        f"Duplicate node id {node_id!s} encountered while parsing {file_path}"
                    )
                merged_nodes[node_id] = node

            merged_edges.extend(edges)

        return merged_nodes, merged_edges

    def _module_name_for_path(self, file_path: Path) -> str:
        rel = file_path.relative_to(self.root)
        rel = rel.parent if rel.name == "__init__.py" else rel.with_suffix("")
        parts = list(rel.parts)
        return ".".join(parts)

    def _parse_exported_names(self, *, file_path: Path) -> _ExportedNames:
        try:
            source_text = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return _ExportedNames(functions={}, classes={}, variables={})

        try:
            tree = ast.parse(source_text, filename=str(file_path))
        except SyntaxError:
            return _ExportedNames(functions={}, classes={}, variables={})

        functions: dict[str, int] = {}
        classes: dict[str, int] = {}
        variables: dict[str, int] = {}

        for stmt in tree.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions[stmt.name] = stmt.lineno
                continue
            if isinstance(stmt, ast.ClassDef):
                classes[stmt.name] = stmt.lineno
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

        return _ExportedNames(functions=functions, classes=classes, variables=variables)

    def _build_symbol_index(
        self,
        *,
        python_files: list[Path],
        module_by_file: dict[Path, str],
    ) -> dict[str, dict[str, NodeID]]:
        index: dict[str, dict[str, NodeID]] = {}

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
                logger.exception("Failed to parse Python file (symbol index): %s", file_path)
                continue

            module_symbols: dict[str, NodeID] = {}

            for name in exported.functions:
                for node_id, node in nodes.items():
                    if getattr(node, "name", None) == name and str(node_id).startswith("function:"):
                        module_symbols[name] = node_id
                        break

            for name in exported.classes:
                for node_id, node in nodes.items():
                    if getattr(node, "name", None) == name and str(node_id).startswith("class:"):
                        module_symbols[name] = node_id
                        break

            for name, lineno in exported.variables.items():
                for node_id, node in nodes.items():
                    if (
                        getattr(node, "name", None) == name
                        and getattr(node, "line_start", None) == lineno
                        and str(node_id).startswith("variable:")
                    ):
                        module_symbols[name] = node_id
                        break

            if module_symbols:
                index[module_name] = module_symbols

        return index

    def _prebound_symbols_for_file(
        self,
        *,
        file_path: Path,
        module_by_file: dict[Path, str],
        symbol_index: dict[str, dict[str, NodeID]],
    ) -> dict[str, NodeID]:
        try:
            source_text = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return {}

        try:
            tree = ast.parse(source_text, filename=str(file_path))
        except SyntaxError:
            return {}

        current_module = module_by_file[file_path]
        prebound: dict[str, NodeID] = {}

        for stmt in tree.body:
            if not isinstance(stmt, ast.ImportFrom):
                continue

            resolved_module = self._resolve_import_from_module(
                current_module=current_module,
                level=stmt.level,
                module=stmt.module,
            )
            if resolved_module is None:
                continue

            if resolved_module not in symbol_index:
                continue

            module_symbols = symbol_index[resolved_module]
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
        level: int,
        module: str | None,
    ) -> str | None:
        if level < 0:
            return None

        current_package = current_module.rsplit(".", 1)[0] if "." in current_module else ""

        # level=0 => absolute import
        if level == 0:
            return module

        # level=1 => current package; level=2 => parent of current package, etc.
        parts = [p for p in current_package.split(".") if p]
        up = level - 1
        if up > len(parts):
            parts = []
        elif up:
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
