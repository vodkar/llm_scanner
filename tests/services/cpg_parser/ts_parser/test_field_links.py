"""Linking class field declarations to the code that writes and reads them."""

from pathlib import Path

from models.base import NodeID
from models.edges.data_flow import DataFlowFlowsTo
from models.nodes import Node
from services.cpg_parser.ts_parser.cpg_builder import CPGDirectoryBuilder
from services.cpg_parser.ts_parser.field_links import (
    FieldAccess,
    FieldDeclaration,
    link_field_accesses,
)

_MODELS = """
class Base:
    pass


class User(Base):
    __tablename__ = "users"
    name: str
    role: str = "user"
    preferred_sort: str = "name"


class Item(Base):
    name: str


class Counter:
    def __init__(self, start):
        self.value = start

    def current(self):
        return self.value
"""

_WRITER = """
from app.models import User


def save_sort(user: User, sort_field):
    user.preferred_sort = sort_field
"""

_READER = """
from app.models import User


def order_clause(field):
    return f"ORDER BY {field}"


def listing(user: User):
    clause = order_clause(user.preferred_sort)
    return clause


def label(user: User):
    return user.name
"""


def _write_project(root: Path) -> None:
    package = root / "app"
    package.mkdir()
    (package / "__init__.py").write_text("")
    (package / "models.py").write_text(_MODELS)
    (package / "writer.py").write_text(_WRITER)
    (package / "reader.py").write_text(_READER)


def _flows(root: Path) -> set[tuple[str, str]]:
    nodes, edges = CPGDirectoryBuilder(root=root).build()

    def describe(node: Node) -> str:
        return f"{node.file_path.name}:{node.line_start}"

    return {
        (describe(nodes[edge.src]), describe(nodes[edge.dst]))
        for edge in edges
        if isinstance(edge, DataFlowFlowsTo) and "models.py" in str(edge.src) + str(edge.dst)
    }


def test_attribute_write_flows_into_field_and_field_into_reads(tmp_path: Path) -> None:
    _write_project(tmp_path)

    flows = _flows(tmp_path)

    assert ("writer.py:6", "models.py:10") in flows
    assert ("models.py:10", "reader.py:10") in flows


def test_self_attribute_declares_field_read_by_method(tmp_path: Path) -> None:
    _write_project(tmp_path)

    assert ("models.py:19", "models.py:21") in _flows(tmp_path)


def test_field_name_declared_by_two_classes_is_not_linked(tmp_path: Path) -> None:
    _write_project(tmp_path)

    assert not any(src.startswith("models.py:7") for src, _ in _flows(tmp_path))


def test_receiver_class_resolves_through_bases() -> None:
    declarations = [FieldDeclaration(NodeID("class:Base"), "value", NodeID("variable:value"))]
    accesses = [
        FieldAccess("value", NodeID("variable:self.value"), True, NodeID("class:Child")),
        FieldAccess("value", NodeID("function:read"), False, NodeID("class:Other")),
    ]

    edges = link_field_accesses(
        declarations, accesses, {NodeID("class:Child"): (NodeID("class:Base"),)}
    )

    assert [(edge.src, edge.dst) for edge in edges] == [
        (NodeID("variable:self.value"), NodeID("variable:value"))
    ]
