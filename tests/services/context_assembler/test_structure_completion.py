"""Tests for structural completion of rendered snippets (issue D).

Ensures the renderer never emits a method/statement without its enclosing
``def``/``class`` header, and never emits a bare class header with no body.
"""

from pathlib import Path

from models.base import NodeID
from models.context import CodeContextNode
from services.context_assembler.context_assembler import ContextAssemblerService
from services.ranking.ranking import DummyNodeRankingStrategy


def _node(
    name: str,
    file_path: str,
    *,
    line_start: int,
    line_end: int,
    depth: int,
    node_kind: str = "FunctionNode",
) -> CodeContextNode:
    return CodeContextNode(
        identifier=NodeID(f"{node_kind}:{name}"),
        node_kind=node_kind,
        name=name,
        file_path=Path(file_path),
        line_start=line_start,
        line_end=line_end,
        depth=depth,
    )


def _service(tmp_path: Path) -> ContextAssemblerService:
    return ContextAssemblerService(
        project_root=tmp_path,
        context_repository=None,
        cached_neighborhood_edges=[],
        max_call_depth=2,
        token_budget=10_000,
        ranking_strategy=DummyNodeRankingStrategy(),
    )


def test_dangling_method_gets_enclosing_class_header(tmp_path: Path) -> None:
    """A selected method renders under its `class X:` header."""

    (tmp_path / "svc.py").write_text(
        "class Service:\n"
        "    def helper(self):\n"
        "        return 1\n"
        "    def vuln(self):\n"
        "        return self.helper()\n",
        encoding="utf-8",
    )

    context = _service(tmp_path).assemble_from_nodes(
        tmp_path, [_node("vuln", "svc.py", line_start=4, line_end=5, depth=0)]
    )

    assert "class Service:" in context.context_text
    assert "def vuln(self):" in context.context_text


def test_empty_class_header_is_dropped(tmp_path: Path) -> None:
    """A class node with no selected member is not rendered as a bare header."""

    (tmp_path / "mod.py").write_text(
        "class Thing:\n"
        "    def real(self):\n"
        "        return 1\n"
        "class EmptyError(Exception):\n"
        "    pass\n",
        encoding="utf-8",
    )

    context = _service(tmp_path).assemble_from_nodes(
        tmp_path,
        [
            _node("real", "mod.py", line_start=2, line_end=3, depth=0),
            _node(
                "EmptyError",
                "mod.py",
                line_start=4,
                line_end=4,
                depth=1,
                node_kind="ClassNode",
            ),
        ],
    )

    assert "class EmptyError" not in context.context_text
    assert "class Thing:" in context.context_text
    assert "def real(self):" in context.context_text


def test_root_class_header_is_protected(tmp_path: Path) -> None:
    """A root class node is kept even when no member is selected."""

    (tmp_path / "marker.py").write_text(
        "class Marker(Exception):\n    pass\n",
        encoding="utf-8",
    )

    context = _service(tmp_path).assemble_from_nodes(
        tmp_path,
        [_node("Marker", "marker.py", line_start=1, line_end=1, depth=0, node_kind="ClassNode")],
    )

    assert "class Marker(Exception):" in context.context_text


def test_unparseable_file_falls_back_without_crash(tmp_path: Path) -> None:
    """A file that is not valid Python renders selected lines without completion."""

    (tmp_path / "broken.py").write_text(
        "def ok(\n    this is not python )(\n    return 1\n",
        encoding="utf-8",
    )

    context = _service(tmp_path).assemble_from_nodes(
        tmp_path, [_node("ok", "broken.py", line_start=1, line_end=3, depth=0)]
    )

    assert "def ok(" in context.context_text


def test_class_node_with_attribute_span_renders_attributes(tmp_path: Path) -> None:
    """A class node spanning its attribute block renders the attributes, not nothing."""

    (tmp_path / "agg.py").write_text(
        "class StringAgg(Aggregate):\n"
        "    template = \"%(function)s(%(expressions)s, '%(delimiter)s')\"\n"
        "    def __init__(self, expression, delimiter):\n"
        "        super().__init__(expression, delimiter=delimiter)\n",
        encoding="utf-8",
    )

    context = _service(tmp_path).assemble_from_nodes(
        tmp_path,
        [
            _node("__init__", "agg.py", line_start=3, line_end=4, depth=0),
            _node("StringAgg", "agg.py", line_start=1, line_end=2, depth=1, node_kind="ClassNode"),
        ],
    )

    assert context.roots[0].context.count("template = ") == 1
