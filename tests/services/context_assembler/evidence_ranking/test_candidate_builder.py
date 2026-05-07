"""Tests for the evidence-aware candidate builder."""

from pathlib import Path

import pytest

from models.context import CodeContextNode
from models.context_ranking import BudgetedRankingConfig
from services.context_assembler.evidence_ranking.candidate_builder import CandidateBuilder
from services.context_assembler.snippet_reader import SnippetReaderService


@pytest.fixture(autouse=True)
def clear_neo4j_database() -> None:
    """Override the global Neo4j autouse fixture for pure unit tests."""

    return None


def _write_module(root: Path, relative: Path, line_count: int) -> None:
    """Write a synthetic Python file with ``line_count`` lines under ``root``."""

    file_path = root / relative
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text("".join(f"line_{i}\n" for i in range(1, line_count + 1)))


def _builder(tmp_path: Path, **overrides: object) -> CandidateBuilder:
    config = BudgetedRankingConfig(**overrides)  # type: ignore[arg-type]
    reader = SnippetReaderService(project_root=tmp_path)
    return CandidateBuilder(project_root=tmp_path, config=config, snippet_reader=reader)


def test_returns_one_candidate_per_unique_node(tmp_path: Path) -> None:
    """Duplicate nodes must collapse into a single candidate (mirrors _aggregate_context_nodes)."""

    _write_module(tmp_path, Path("a.py"), line_count=20)

    nodes = [
        CodeContextNode(
            identifier="n1",  # type: ignore[arg-type]
            file_path=Path("a.py"),
            line_start=1,
            line_end=10,
            depth=2,
            repeats=0,
        ),
        CodeContextNode(
            identifier="n1",  # type: ignore[arg-type]
            file_path=Path("a.py"),
            line_start=1,
            line_end=10,
            depth=1,
            repeats=0,
        ),
    ]

    candidates = _builder(tmp_path).build(nodes)

    assert len(candidates) == 1
    assert candidates[0].source_node.depth == 1
    assert candidates[0].source_node.repeats >= 1


def test_preserves_input_order_for_unique_nodes(tmp_path: Path) -> None:
    """Order of first occurrence must be preserved across unique nodes."""

    _write_module(tmp_path, Path("a.py"), line_count=20)
    _write_module(tmp_path, Path("b.py"), line_count=20)

    nodes = [
        CodeContextNode(
            identifier="b1",  # type: ignore[arg-type]
            file_path=Path("b.py"),
            line_start=1,
            line_end=5,
            depth=1,
        ),
        CodeContextNode(
            identifier="a1",  # type: ignore[arg-type]
            file_path=Path("a.py"),
            line_start=1,
            line_end=5,
            depth=2,
        ),
    ]

    candidates = _builder(tmp_path).build(nodes)
    identifiers = [c.source_node.identifier for c in candidates]

    assert identifiers == ["b1", "a1"]


def test_estimates_tokens_with_assembler_formula(tmp_path: Path) -> None:
    """Token estimation must use max(1, len(text)//3) — the same formula as the renderer."""

    _write_module(tmp_path, Path("a.py"), line_count=10)
    snippet = (tmp_path / "a.py").read_text()
    expected_tokens = max(1, len(snippet) // 3)

    nodes = [
        CodeContextNode(
            identifier="a",  # type: ignore[arg-type]
            file_path=Path("a.py"),
            line_start=1,
            line_end=10,
            depth=0,
        ),
    ]
    [candidate] = _builder(tmp_path).build(nodes)

    assert candidate.estimated_token_count == expected_tokens


def test_clips_line_range_when_over_threshold(tmp_path: Path) -> None:
    """Nodes over small_node_token_threshold must clip to ±radius around line_start."""

    _write_module(tmp_path, Path("a.py"), line_count=200)

    nodes = [
        CodeContextNode(
            identifier="big",  # type: ignore[arg-type]
            file_path=Path("a.py"),
            line_start=100,
            line_end=199,
            depth=2,
        ),
    ]
    [candidate] = _builder(
        tmp_path,
        small_node_token_threshold=10,
        local_window_radius=5,
    ).build(nodes)

    assert candidate.clipped_line_start == 95
    assert candidate.clipped_line_end == 105
    assert candidate.estimated_token_count < 200  # smaller than the unclipped span


def test_keeps_full_range_when_under_threshold(tmp_path: Path) -> None:
    """Nodes within budget must keep their original line range."""

    _write_module(tmp_path, Path("a.py"), line_count=20)

    nodes = [
        CodeContextNode(
            identifier="small",  # type: ignore[arg-type]
            file_path=Path("a.py"),
            line_start=3,
            line_end=8,
            depth=1,
        ),
    ]
    [candidate] = _builder(tmp_path, small_node_token_threshold=10_000).build(nodes)

    assert candidate.clipped_line_start == 3
    assert candidate.clipped_line_end == 8


def test_clipped_lower_bound_at_line_one(tmp_path: Path) -> None:
    """Clipping near the top of a file must clamp to line 1, not go negative."""

    _write_module(tmp_path, Path("a.py"), line_count=50)

    nodes = [
        CodeContextNode(
            identifier="top",  # type: ignore[arg-type]
            file_path=Path("a.py"),
            line_start=2,
            line_end=40,
            depth=0,
        ),
    ]
    [candidate] = _builder(
        tmp_path,
        small_node_token_threshold=10,
        local_window_radius=5,
    ).build(nodes)

    assert candidate.clipped_line_start == 1
    assert candidate.clipped_line_end == 7


def test_starts_with_empty_roles_and_zero_scores(tmp_path: Path) -> None:
    """Candidates begin un-annotated; roles and scores are filled by later stages."""

    _write_module(tmp_path, Path("a.py"), line_count=10)

    nodes = [
        CodeContextNode(
            identifier="x",  # type: ignore[arg-type]
            file_path=Path("a.py"),
            line_start=1,
            line_end=5,
            depth=0,
        ),
    ]
    [candidate] = _builder(tmp_path).build(nodes)

    assert candidate.roles == frozenset()
    assert candidate.distance_score == 0.0
    assert candidate.context_score == 0.0
    assert candidate.relevance == 0.0


def test_empty_input_returns_empty_list(tmp_path: Path) -> None:
    """The builder must handle the empty-input case gracefully."""

    assert _builder(tmp_path).build([]) == []
