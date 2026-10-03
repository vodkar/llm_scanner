"""Method names live in class scope: bare-name calls never resolve to them."""

from pathlib import Path
from typing import Final

from models.base import NodeID
from models.nodes import Node
from models.nodes.call_site import CallNode
from models.nodes.code import FunctionNode
from services.cpg_parser.ts_parser.cpg_builder import CPGDirectoryBuilder, CPGFileBuilder

SHADOWED_FUNCTION_SOURCE: Final[str] = """\
def save(value):
    return value


class Repo:
    def save(self, value):
        return save(value)


def run():
    return save(1)
"""

BUILTIN_BEFORE_CLASS_SOURCE: Final[str] = """\
def read(path):
    return open(path)


class Connection:
    def open(self):
        return 1
"""

BUILTIN_AFTER_DECORATED_METHOD_SOURCE: Final[str] = """\
import functools


class Connection:
    @functools.cache
    def open(self):
        return 1


def read(path):
    return open(path)
"""

HELPER_SOURCE: Final[str] = """\
def helper():
    return 1
"""

IMPORT_SHADOWED_BY_METHOD_SOURCE: Final[str] = """\
from utils import helper


class Foo:
    def helper(self):
        return helper()
"""

METHOD_BEFORE_FUNCTION_SOURCE: Final[str] = """\
class Repo:
    def save(self, value):
        return value


def save(value):
    return value


def store(repo):
    return repo.save(2)
"""

METHOD_AFTER_CALLER_SOURCE: Final[str] = """\
def use(connection):
    return connection.open()


class Connection:
    def open(self):
        return 1
"""


def _call_links(nodes: dict[NodeID, Node]) -> set[tuple[str, str, int]]:
    """Return ``(caller name, callee file name, callee line)`` for every resolved call."""

    return {
        (caller.name, callee.file_path.name, callee.line_start)
        for node in nodes.values()
        if isinstance(node, CallNode)
        if isinstance(caller := nodes[node.caller_id], FunctionNode)
        if isinstance(callee := nodes[node.callee_id], FunctionNode)
    }


def _file_call_links(tmp_path: Path, source: str) -> set[tuple[str, str, int]]:
    file_path: Path = tmp_path / "module.py"
    file_path.write_text(source, encoding="utf-8")
    nodes, _edges = CPGFileBuilder(path=file_path, root=tmp_path).build()
    return _call_links(nodes)


def test_bare_call__resolves_to_module_function_not_same_named_method(tmp_path: Path) -> None:
    links = _file_call_links(tmp_path, SHADOWED_FUNCTION_SOURCE)

    assert links == {("save", "module.py", 1), ("run", "module.py", 1)}


def test_bare_builtin_call__is_not_linked_to_method_defined_later(tmp_path: Path) -> None:
    assert _file_call_links(tmp_path, BUILTIN_BEFORE_CLASS_SOURCE) == set()


def test_bare_builtin_call__is_not_linked_to_decorated_method(tmp_path: Path) -> None:
    assert _file_call_links(tmp_path, BUILTIN_AFTER_DECORATED_METHOD_SOURCE) == set()


def test_bare_call__imported_function_is_not_shadowed_by_method(tmp_path: Path) -> None:
    (tmp_path / "utils.py").write_text(HELPER_SOURCE, encoding="utf-8")
    (tmp_path / "main.py").write_text(IMPORT_SHADOWED_BY_METHOD_SOURCE, encoding="utf-8")

    nodes, _edges = CPGDirectoryBuilder(root=tmp_path).build()

    assert _call_links(nodes) == {("helper", "utils.py", 1)}


def test_attribute_call__prefers_method_over_same_named_module_function(tmp_path: Path) -> None:
    links = _file_call_links(tmp_path, METHOD_BEFORE_FUNCTION_SOURCE)

    assert links == {("store", "module.py", 2)}


def test_attribute_call__resolves_to_method_of_class_defined_later(tmp_path: Path) -> None:
    links = _file_call_links(tmp_path, METHOD_AFTER_CALLER_SOURCE)

    assert links == {("use", "module.py", 6)}
