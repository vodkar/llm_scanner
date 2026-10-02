"""Cross-file call resolution for attribute calls (module aliases, inheritance, methods)."""

from pathlib import Path
from typing import Final

import pytest

from models.base import NodeID
from models.edges.base import RelationshipBase
from models.edges.call_graph import CallGraphCalledBy
from models.nodes import Node
from models.nodes.call_site import CallNode
from models.nodes.code import FunctionNode
from services.cpg_parser.ts_parser.cpg_builder import CPGDirectoryBuilder
from tests.consts import CROSS_FILE_CALLS_PROJECT_ROOT

VIEWS_FILE: Final[Path] = Path("pkg/views.py")

type ParsedProject = tuple[dict[NodeID, Node], list[RelationshipBase]]


@pytest.fixture(scope="module")
def parsed_project() -> ParsedProject:
    return CPGDirectoryBuilder(root=CROSS_FILE_CALLS_PROJECT_ROOT).build()


def _callees_on_line(project: ParsedProject, line: int) -> set[tuple[str, str]]:
    """Return ``(callee name, callee file)`` for calls on ``line`` of views.py."""

    nodes, edges = project
    call_ids: set[NodeID] = {
        node_id
        for node_id, node in nodes.items()
        if isinstance(node, CallNode) and node.file_path == VIEWS_FILE and node.line_start == line
    }
    callees: set[tuple[str, str]] = set()
    for edge in edges:
        if not isinstance(edge, CallGraphCalledBy) or edge.src not in call_ids:
            continue
        callee = nodes[edge.dst]
        if isinstance(callee, FunctionNode):
            callees.add((callee.name, str(callee.file_path)))
    return callees


def _line_of(needle: str) -> int:
    lines: list[str] = (CROSS_FILE_CALLS_PROJECT_ROOT / VIEWS_FILE).read_text().splitlines()
    return next(number for number, text in enumerate(lines, start=1) if needle in text)


def test_module_imported_from_package__resolves_module_attribute_call(
    parsed_project: ParsedProject,
) -> None:
    line: int = _line_of("helpers.sanitize(value)")

    assert ("sanitize", "pkg/helpers.py") in _callees_on_line(parsed_project, line)


def test_aliased_module_import__resolves_module_attribute_call(
    parsed_project: ParsedProject,
) -> None:
    line: int = _line_of("h.sanitize(value)")

    assert ("sanitize", "pkg/helpers.py") in _callees_on_line(parsed_project, line)


def test_self_call__resolves_method_inherited_from_base_in_other_file(
    parsed_project: ParsedProject,
) -> None:
    line: int = _line_of('self.run(["clone", url])')

    assert _callees_on_line(parsed_project, line) == {("run", "pkg/base.py")}


def test_super_call__resolves_base_class_method_in_other_file(
    parsed_project: ParsedProject,
) -> None:
    line: int = _line_of("super().run(args)")

    assert _callees_on_line(parsed_project, line) == {("run", "pkg/base.py")}


def test_method_call_on_untyped_object__resolves_repo_unique_method(
    parsed_project: ParsedProject,
) -> None:
    line: int = _line_of("song.get_related_songs_json(top)")

    assert _callees_on_line(parsed_project, line) == {("get_related_songs_json", "pkg/models.py")}


def test_method_call_named_like_builtin_type_method__stays_unresolved(
    parsed_project: ParsedProject,
) -> None:
    line: int = _line_of("data.items()")

    assert _callees_on_line(parsed_project, line) == set()
