"""Roots and their context are rendered as separate, per-root sections."""

from pathlib import Path

from models.base import NodeID
from models.context import CodeContextNode, Context
from services.context_assembler.context_assembler import ContextAssemblerService
from services.ranking.ranking import DummyNodeRankingStrategy

_APP = (
    "def source_a():\n"  # 1
    "    return input()\n"  # 2
    "def root_a():\n"  # 3
    "    os.system(source_a())\n"  # 4
    "def root_b():\n"  # 5
    "    eval(source_b())\n"  # 6
    "def source_b():\n"  # 7
    "    return input()\n"  # 8
)


def _node(
    name: str, line_start: int, line_end: int, depth: int, kind: str = "FunctionNode"
) -> CodeContextNode:
    return CodeContextNode(
        identifier=NodeID(f"{kind}:{name}"),
        node_kind=kind,
        name=name,
        file_path=Path("app.py"),
        line_start=line_start,
        line_end=line_end,
        depth=depth,
    )


def _edge(src: str, dst: str) -> tuple[NodeID, NodeID, str]:
    return NodeID(f"FunctionNode:{src}"), NodeID(f"FunctionNode:{dst}"), "CALLS"


def _assemble(tmp_path: Path, nodes: list[CodeContextNode]) -> Context:
    (tmp_path / "app.py").write_text(_APP, encoding="utf-8")
    service = ContextAssemblerService(
        project_root=tmp_path,
        context_repository=None,
        cached_neighborhood_edges=[_edge("root_a", "source_a"), _edge("root_b", "source_b")],
        max_call_depth=2,
        token_budget=10_000,
        ranking_strategy=DummyNodeRankingStrategy(),
    )
    return service.assemble_from_nodes(tmp_path, nodes)


def test_each_root_gets_only_its_own_context(tmp_path: Path) -> None:
    context = _assemble(
        tmp_path,
        [
            _node("root_a", 3, 4, depth=0),
            _node("root_b", 5, 6, depth=0),
            _node("source_a", 1, 2, depth=1),
            _node("source_b", 7, 8, depth=1),
        ],
    )

    first, second = context.roots
    assert (first.line_start, first.line_end) == (3, 4)
    assert first.code == "def root_a():\n    os.system(source_a())"
    assert "def source_a():" in first.context
    assert "source_b" not in first.context
    assert second.code == "def root_b():\n    eval(source_b())"
    assert "def source_b():" in second.context
    assert "source_a" not in second.context


def test_rendered_text_marks_roots_and_their_context(tmp_path: Path) -> None:
    context = _assemble(
        tmp_path,
        [
            _node("root_a", 3, 4, depth=0),
            _node("root_b", 5, 6, depth=0),
            _node("source_a", 1, 2, depth=1),
            _node("source_b", 7, 8, depth=1),
        ],
    )

    lines = context.context_text.split("\n")
    assert lines[0].startswith("# ===== ROOT 1/2: app.py:3-4")
    assert lines[1:3] == ["def root_a():", "    os.system(source_a())"]
    assert lines[3].startswith("# ----- CONTEXT for ROOT 1")
    assert lines[4] == "# file: app.py"
    assert lines[5:7] == ["def source_a():", "    return input()"]
    assert lines[7].startswith("# ===== ROOT 2/2: app.py:5-6")


def test_nested_root_nodes_form_one_root(tmp_path: Path) -> None:
    context = _assemble(
        tmp_path,
        [
            _node("root_a", 3, 4, depth=0),
            _node("cmd", 4, 4, depth=0, kind="VariableNode"),
            _node("source_a", 1, 2, depth=1),
        ],
    )

    [root] = context.roots
    assert root.code == "def root_a():\n    os.system(source_a())"
    assert root.context == "# file: app.py\ndef source_a():\n    return input()"


def test_root_lines_are_not_repeated_in_context(tmp_path: Path) -> None:
    context = _assemble(
        tmp_path,
        [_node("root_a", 3, 4, depth=0), _node("module", 1, 8, depth=1, kind="CodeBlockNode")],
    )

    [root] = context.roots
    assert "root_a" not in root.context
    assert context.context_text.count("def root_a():") == 1


def test_root_without_context_has_no_context_section(tmp_path: Path) -> None:
    context = _assemble(tmp_path, [_node("root_a", 3, 4, depth=0)])

    [root] = context.roots
    assert root.context == ""
    assert "CONTEXT" not in context.context_text
