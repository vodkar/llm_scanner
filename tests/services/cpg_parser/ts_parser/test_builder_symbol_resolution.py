"""Regression tests for symbol resolution in the CPG directory and file builders."""

import os
from pathlib import Path
from typing import Final, Literal

import pytest

from models.base import NodeID
from models.edges.call_graph import CallGraphCalledBy
from models.nodes import Node
from models.nodes.call_site import CallNode
from models.nodes.code import CodeBlockNode, FunctionNode
from services.cpg_parser.ts_parser.cpg_builder import CPGDirectoryBuilder, CPGFileBuilder

CORE_SOURCE: Final[str] = """\
class Box:
    def helper(self):
        return 1


def helper():
    return 2


def redefined():
    return "old"


def redefined():
    return "new"
"""

USER_SOURCE: Final[str] = """\
from pkg.core import helper, redefined


def run():
    helper()
    redefined()
"""

INIT_SOURCE: Final[str] = """\
from .core import helper
from . import util


def boot():
    helper()
    util.tool()
"""

UTIL_SOURCE: Final[str] = """\
def tool():
    return 3
"""

HELPER_SOURCE: Final[str] = """\
def helper():
    return 1
"""

HELPER_USER_SOURCE: Final[str] = """\
from utils import helper


def run():
    return helper()
"""

MODELS_SOURCE: Final[str] = """\
class Base:
    def save(self):
        return 1


class Unrelated:
    def save(self):
        return 2


class User(Base):
    def store(self):
        return self.save()
"""

LEGACY_MODELS_SOURCE: Final[str] = """\
class Other:
    def save(self):
        return 0
"""

BEYOND_ROOT_SYMBOL_IMPORT_SOURCE: Final[str] = """\
from ...other import helper


def run():
    return helper()
"""

BEYOND_ROOT_MODULE_IMPORT_SOURCE: Final[str] = """\
from ... import other


def run():
    return other.helper()
"""


def _write_project(root: Path, files: dict[str, str]) -> None:
    for relative_path, source in files.items():
        file_path: Path = root / relative_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(source, encoding="utf-8")


def _callees_from_file(
    nodes: dict[NodeID, Node], edges: list[CallGraphCalledBy], file_path: Path
) -> set[tuple[str, int]]:
    call_ids: set[NodeID] = {
        node_id
        for node_id, node in nodes.items()
        if isinstance(node, CallNode) and node.file_path == file_path
    }
    return {
        (callee.name, callee.line_start)
        for edge in edges
        if edge.src in call_ids
        if isinstance(callee := nodes[edge.dst], FunctionNode)
    }


def _build_callees(root: Path, file_path: Path) -> set[tuple[str, int]]:
    nodes, edges = CPGDirectoryBuilder(root=root).build()
    call_edges: list[CallGraphCalledBy] = [
        edge for edge in edges if isinstance(edge, CallGraphCalledBy)
    ]
    return _callees_from_file(nodes, call_edges, file_path)


def _build_callee_files(
    root: Path, file_path: Path, on_error: Literal["raise", "skip"] = "raise"
) -> set[str]:
    nodes, edges = CPGDirectoryBuilder(root=root, on_error=on_error).build()
    call_ids: set[NodeID] = {
        node_id
        for node_id, node in nodes.items()
        if isinstance(node, CallNode) and node.file_path == file_path
    }
    return {
        str(callee.file_path)
        for edge in edges
        if isinstance(edge, CallGraphCalledBy) and edge.src in call_ids
        if isinstance(callee := nodes[edge.dst], FunctionNode)
    }


def test_imported_function__ignores_same_named_method_defined_earlier(tmp_path: Path) -> None:
    _write_project(
        tmp_path,
        {"pkg/__init__.py": "", "pkg/core.py": CORE_SOURCE, "pkg/user.py": USER_SOURCE},
    )

    callees = _build_callees(tmp_path, Path("pkg/user.py"))

    assert ("helper", 6) in callees
    assert ("helper", 2) not in callees


def test_imported_function__binds_last_redefinition(tmp_path: Path) -> None:
    _write_project(
        tmp_path,
        {"pkg/__init__.py": "", "pkg/core.py": CORE_SOURCE, "pkg/user.py": USER_SOURCE},
    )

    callees = _build_callees(tmp_path, Path("pkg/user.py"))

    assert ("redefined", 14) in callees
    assert ("redefined", 10) not in callees


def test_package_init__resolves_relative_imports_against_itself(tmp_path: Path) -> None:
    _write_project(
        tmp_path,
        {
            "pkg/__init__.py": INIT_SOURCE,
            "pkg/core.py": CORE_SOURCE,
            "pkg/util.py": UTIL_SOURCE,
        },
    )

    callees = _build_callees(tmp_path, Path("pkg/__init__.py"))

    assert ("helper", 6) in callees
    assert ("tool", 1) in callees


def test_file_builder__form_feed_does_not_shift_line_lookup(tmp_path: Path) -> None:
    with_form_feed: Path = tmp_path / "with_form_feed.py"
    with_space: Path = tmp_path / "with_space.py"
    with_form_feed.write_bytes(b"import os\n\x0c\nX = 1\nprint(X)\n")
    with_space.write_bytes(b"import os\n \nX = 1\nprint(X)\n")

    def block_names(path: Path) -> list[str]:
        nodes, _edges = CPGFileBuilder(path=path, root=tmp_path).build()
        return sorted(
            str(node_id).split("@", 1)[0]
            for node_id, node in nodes.items()
            if isinstance(node, CodeBlockNode)
        )

    assert block_names(with_form_feed) == block_names(with_space)


def test_utf8_bom_module__exports_are_importable(tmp_path: Path) -> None:
    _write_project(
        tmp_path,
        {"utils.py": f"\ufeff{HELPER_SOURCE}", "main.py": HELPER_USER_SOURCE},
    )

    assert _build_callee_files(tmp_path, Path("main.py")) == {"utils.py"}


def test_encoding_cookie_module__imports_resolve(tmp_path: Path) -> None:
    _write_project(tmp_path, {"utils.py": HELPER_SOURCE})
    (tmp_path / "main.py").write_bytes(
        b"# -*- coding: latin-1 -*-\n# caf\xe9\n" + HELPER_USER_SOURCE.encode("ascii")
    )

    assert _build_callee_files(tmp_path, Path("main.py")) == {"utils.py"}


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file permissions")
def test_skip_mode__unreadable_file_does_not_abort_build(tmp_path: Path) -> None:
    _write_project(
        tmp_path,
        {"utils.py": HELPER_SOURCE, "main.py": HELPER_USER_SOURCE, "locked.py": "X = 1\n"},
    )
    (tmp_path / "locked.py").chmod(0)

    assert _build_callee_files(tmp_path, Path("main.py"), on_error="skip") == {"utils.py"}


def test_absolute_import__prefers_exact_module_over_nested_alias(tmp_path: Path) -> None:
    _write_project(
        tmp_path,
        {
            "scripts/utils.py": HELPER_SOURCE,
            "utils.py": HELPER_SOURCE,
            "main.py": HELPER_USER_SOURCE,
        },
    )

    assert _build_callee_files(tmp_path, Path("main.py")) == {"utils.py"}


def test_absolute_import__prefers_module_in_importers_source_root(tmp_path: Path) -> None:
    _write_project(
        tmp_path,
        {
            "jobs/utils.py": HELPER_SOURCE,
            "tools/utils.py": HELPER_SOURCE,
            "tools/main.py": HELPER_USER_SOURCE,
        },
    )

    assert _build_callee_files(tmp_path, Path("tools/main.py")) == {"tools/utils.py"}


def test_absolute_import__skips_alias_claimed_by_several_modules(tmp_path: Path) -> None:
    _write_project(
        tmp_path,
        {
            "jobs/utils.py": HELPER_SOURCE,
            "tools/utils.py": HELPER_SOURCE,
            "main.py": HELPER_USER_SOURCE,
        },
    )

    assert _build_callee_files(tmp_path, Path("main.py")) == set()


def test_absolute_import__resolves_unique_alias_from_other_source_root(tmp_path: Path) -> None:
    _write_project(
        tmp_path,
        {"lib/utils.py": HELPER_SOURCE, "main.py": HELPER_USER_SOURCE},
    )

    assert _build_callee_files(tmp_path, Path("main.py")) == {"lib/utils.py"}


def test_inherited_method__resolves_when_module_name_is_also_a_nested_alias(
    tmp_path: Path,
) -> None:
    _write_project(
        tmp_path,
        {"legacy/models.py": LEGACY_MODELS_SOURCE, "models.py": MODELS_SOURCE},
    )

    assert _build_callees(tmp_path, Path("models.py")) == {("save", 2)}


@pytest.mark.parametrize(
    "importer_source",
    [BEYOND_ROOT_SYMBOL_IMPORT_SOURCE, BEYOND_ROOT_MODULE_IMPORT_SOURCE],
    ids=["symbol", "module"],
)
def test_relative_import_beyond_root__is_not_linked(tmp_path: Path, importer_source: str) -> None:
    _write_project(
        tmp_path,
        {"other.py": HELPER_SOURCE, "pkg/__init__.py": "", "pkg/mod.py": importer_source},
    )

    assert _build_callee_files(tmp_path, Path("pkg/mod.py")) == set()
