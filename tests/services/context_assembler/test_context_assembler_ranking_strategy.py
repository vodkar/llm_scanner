"""Tests for ranking strategy injection in ContextAssemblerService."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from models.base import NodeID
from models.context import CodeContextNode, FileSpans
from repositories.context import ContextRepository
from services.context_assembler.context_assembler import ContextAssemblerService
from services.context_assembler.ranking import ContextNodeRankingStrategy


class FakeContextRepository(ContextRepository):
    """Minimal repository stub for context assembler tests."""

    context_nodes: list[CodeContextNode]
    spans_nodes: list[CodeContextNode] | None = None
    proximity_scores: dict[NodeID, float] = {}
    proximity_call_log: list[Any] = []

    def model_post_init(self, __context: Any) -> None:
        """Skip Neo4j initialization for a pure unit test stub."""

        del __context

    def fetch_code_nodes_by_file_lines(
        self,
        rows: list[dict[str, object]],
    ) -> list[CodeContextNode]:
        """Return the configured span nodes or the first context node."""

        del rows
        if self.spans_nodes is not None:
            return list(self.spans_nodes)
        return [self.context_nodes[0]]

    def fetch_code_neighborhood_batch(
        self,
        start_node_ids: list[str],
        max_depth: int,
    ) -> list[CodeContextNode]:
        """Return the configured context neighborhood."""

        del start_node_ids, max_depth
        return self.context_nodes

    def fetch_taint_sources(
        self,
        root_node_ids: list[str],
        max_taint_depth: int = 6,
    ) -> dict[NodeID, float]:
        """Return empty taint scores for unit test stub."""

        del root_node_ids, max_taint_depth
        return {}

    def fetch_finding_proximity_scores(
        self,
        anchor_evidence: dict[NodeID, float],
        max_depth: int,
    ) -> dict[NodeID, float]:
        """Record arguments and return configured proximity scores."""

        self.proximity_call_log.append((dict(anchor_evidence), max_depth))
        return dict(self.proximity_scores)


class ReverseRankingStrategy(ContextNodeRankingStrategy):
    """Return nodes in reverse order for injection tests."""

    def rank_nodes(self, nodes: list[CodeContextNode]) -> list[CodeContextNode]:
        """Reverse the provided node list.

        Args:
            nodes: Retrieved context nodes.

        Returns:
            Reversed nodes.
        """

        return list(reversed(nodes))


def test_context_assembler_uses_injected_ranking_strategy(tmp_path: Path) -> None:
    """Injected strategy should control which snippet is rendered first."""

    alpha_file = tmp_path / "alpha.py"
    beta_file = tmp_path / "beta.py"
    alpha_file.write_text(
        "def alpha_function_name():\n    return 'alpha-value'\n",
        encoding="utf-8",
    )
    beta_file.write_text(
        "def beta_function_name():\n    return 'beta-value'\n",
        encoding="utf-8",
    )

    alpha_node = CodeContextNode(
        identifier=NodeID("function:alpha"),
        node_kind="FunctionNode",
        name="alpha_function_name",
        file_path=Path("alpha.py"),
        line_start=1,
        line_end=2,
        depth=0,
    )
    beta_node = CodeContextNode(
        identifier=NodeID("function:beta"),
        node_kind="FunctionNode",
        name="beta_function_name",
        file_path=Path("beta.py"),
        line_start=1,
        line_end=2,
        depth=1,
    )

    service = ContextAssemblerService(
        project_root=tmp_path,
        context_repository=FakeContextRepository.model_construct(
            client=None,
            context_nodes=[alpha_node, beta_node],
            traversal_relationship_types=(),
        ),
        max_call_depth=2,
        token_budget=18,
        ranking_strategy=ReverseRankingStrategy(),
    )

    context = service.assemble_for_spans(
        tmp_path,
        [FileSpans(tmp_path / "alpha.py", [(1, 1)])],
    )

    assert "def beta_function_name" in context.context_text
    assert "def alpha_function_name" not in context.context_text


class CapturingRankingStrategy(ContextNodeRankingStrategy):
    """Record nodes passed to ranking, return them unchanged."""

    captured: list[CodeContextNode] = []

    def rank_nodes(self, nodes: list[CodeContextNode]) -> list[CodeContextNode]:
        """Record the supplied nodes and return them as-is.

        Args:
            nodes: Retrieved context nodes.

        Returns:
            The same nodes, unmodified.
        """

        self.captured = list(nodes)
        return nodes


def test_assemble_for_spans_applies_finding_proximity_scores(tmp_path: Path) -> None:
    """Assembler threads proximity scores onto matching context nodes."""

    anchor_file = tmp_path / "anchor.py"
    neighbor_file = tmp_path / "neighbor.py"
    anchor_file.write_text(
        "def anchor_function():\n    return 'anchor'\n",
        encoding="utf-8",
    )
    neighbor_file.write_text(
        "def neighbor_function():\n    return 'neighbor'\n",
        encoding="utf-8",
    )

    anchor_node = CodeContextNode(
        identifier=NodeID("a1"),
        node_kind="FunctionNode",
        name="anchor_function",
        file_path=Path("anchor.py"),
        line_start=1,
        line_end=2,
        depth=0,
        finding_evidence_score=0.8,
    )
    neighbor_node = CodeContextNode(
        identifier=NodeID("n1"),
        node_kind="FunctionNode",
        name="neighbor_function",
        file_path=Path("neighbor.py"),
        line_start=1,
        line_end=2,
        depth=1,
    )

    fake_repo = FakeContextRepository.model_construct(
        client=None,
        context_nodes=[anchor_node, neighbor_node],
        spans_nodes=[anchor_node],
        proximity_scores={NodeID("n1"): 0.85},
        proximity_call_log=[],
        traversal_relationship_types=(),
    )
    ranking = CapturingRankingStrategy()

    service = ContextAssemblerService(
        project_root=tmp_path,
        context_repository=fake_repo,
        max_call_depth=3,
        token_budget=1000,
        ranking_strategy=ranking,
    )

    service.assemble_for_spans(
        tmp_path,
        [FileSpans(tmp_path / "anchor.py", [(1, 1)])],
    )

    assert len(fake_repo.proximity_call_log) == 1
    anchors_arg, depth_arg = fake_repo.proximity_call_log[0]
    assert anchors_arg == {NodeID("a1"): 0.8}
    assert depth_arg == 3

    matching = [n for n in ranking.captured if n.identifier == NodeID("n1")]
    assert len(matching) == 1
    assert matching[0].finding_proximity_score == pytest.approx(0.85)
