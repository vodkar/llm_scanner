"""Tests for comment stripping and robust file/line reads at render time."""

from pathlib import Path

from models.base import NodeID
from models.context import CodeContextNode
from services.context_assembler.context_assembler import ContextAssemblerService
from services.ranking.ranking import DummyNodeRankingStrategy


def _node(name: str, file_path: str, line_start: int, line_end: int) -> CodeContextNode:
    return CodeContextNode(
        identifier=NodeID(f"function:{name}"),
        node_kind="FunctionNode",
        name=name,
        file_path=Path(file_path),
        line_start=line_start,
        line_end=line_end,
        depth=0,
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


def test_hash_inside_string_literal_is_preserved(tmp_path: Path) -> None:
    """A ``#`` inside quotes is code, not a comment; trailing comments still go."""

    body = "URL = \"https://host/path#anchor\"  # base endpoint\ncolor = '#fff'\n"
    (tmp_path / "a.py").write_text(body, encoding="utf-8")

    context = _service(tmp_path).assemble_from_nodes(tmp_path, [_node("a", "a.py", 1, 2)])

    assert '"https://host/path#anchor"' in context.context_text
    assert "'#fff'" in context.context_text
    assert "base endpoint" not in context.context_text


def test_out_of_range_line_span_is_clamped(tmp_path: Path) -> None:
    """A node whose span exceeds the file length renders the existing lines."""

    (tmp_path / "a.py").write_text("first = 1\nsecond = 2\n", encoding="utf-8")

    context = _service(tmp_path).assemble_from_nodes(tmp_path, [_node("a", "a.py", 1, 10)])

    assert "first = 1" in context.context_text
    assert "second = 2" in context.context_text


def test_missing_file_is_skipped(tmp_path: Path) -> None:
    """A node pointing at a deleted file must not break rendering of the rest."""

    (tmp_path / "a.py").write_text("kept = True\n", encoding="utf-8")

    context = _service(tmp_path).assemble_from_nodes(
        tmp_path,
        [_node("gone", "missing.py", 1, 3), _node("a", "a.py", 1, 1)],
    )

    assert "kept = True" in context.context_text
