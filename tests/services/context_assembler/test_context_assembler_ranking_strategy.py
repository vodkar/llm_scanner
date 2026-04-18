"""Tests for ranking strategy injection in ContextAssemblerService."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from models.base import NodeID
from models.context import CodeContextNode, FileSpans
from repositories.context import ContextRepository
from services.context_assembler.context_assembler import ContextAssemblerService
from services.context_assembler.ranking import ContextNodeRankingStrategy


class FakeContextRepository(ContextRepository):
    """Minimal repository stub for context assembler tests."""

    context_nodes: list[CodeContextNode]

    def model_post_init(self, __context: Any) -> None:
        """Skip Neo4j initialization for a pure unit test stub."""

        del __context

    def fetch_code_nodes_by_file_lines(
        self,
        _: list[dict[str, object]],
    ) -> list[CodeContextNode]:
        """Return the first node as the span match."""

        return [self.context_nodes[0]]

    def fetch_code_neighborhood_batch(
        self,
        _: list[str],
        __: int,
    ) -> list[CodeContextNode]:
        """Return the configured context neighborhood."""

        return self.context_nodes

    def fetch_taint_sources(
        self,
        _: list[str],
        __: int = 6,
    ) -> dict[NodeID, float]:
        """Return empty taint scores for unit test stub."""

        return {}


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
