"""End-to-end tests for the EvidenceAwareBudgetedNodeRankingStrategy."""

from pathlib import Path

import pytest

from models.context import CodeContextNode
from models.context_ranking import BudgetedRankingConfig
from services.context_assembler.evidence_ranking.strategy import (
    EvidenceAwareBudgetedNodeRankingStrategy,
)
from services.context_assembler.ranking import ContextNodeRankingStrategy


@pytest.fixture(autouse=True)
def clear_neo4j_database() -> None:
    """Override the global Neo4j autouse fixture for pure unit tests."""

    return None


def _write(root: Path, relative: Path, content: str) -> None:
    file_path = root / relative
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(content)


def _strategy(
    project_root: Path,
    *,
    token_budget: int = 8192,
    config: BudgetedRankingConfig | None = None,
) -> EvidenceAwareBudgetedNodeRankingStrategy:
    return EvidenceAwareBudgetedNodeRankingStrategy(
        project_root=project_root,
        token_budget=token_budget,
        config=config or BudgetedRankingConfig(),
    )


def test_implements_ranking_strategy_contract(tmp_path: Path) -> None:
    strategy = _strategy(tmp_path)

    assert isinstance(strategy, ContextNodeRankingStrategy)
    assert strategy.requires_edge_paths is True


def test_empty_input_returns_empty_list(tmp_path: Path) -> None:
    """The strategy must handle an empty node list without crashing."""

    assert _strategy(tmp_path).rank_nodes([]) == []


def test_ranks_root_node_first(tmp_path: Path) -> None:
    """Root nodes (depth=0) must appear first in the ranked output."""

    _write(tmp_path, Path("a.py"), "x = 1\nsubprocess.run(cmd)\nval = 2\n")

    nodes = [
        CodeContextNode(
            identifier="far",  # type: ignore[arg-type]
            file_path=Path("a.py"),
            line_start=3,
            line_end=3,
            depth=2,
        ),
        CodeContextNode(
            identifier="root",  # type: ignore[arg-type]
            file_path=Path("a.py"),
            line_start=2,
            line_end=2,
            depth=0,
        ),
    ]

    ranked = _strategy(tmp_path).rank_nodes(nodes)

    assert ranked[0].identifier == "root"


def test_deprioritizes_generated_files(tmp_path: Path) -> None:
    """Boilerplate (generated) files must rank below substantive code."""

    _write(tmp_path, Path("real.py"), "subprocess.run(user_input)\n")
    _write(tmp_path, Path("schema_pb2.py"), "subprocess.run(x)\n")

    nodes = [
        CodeContextNode(
            identifier="boilerplate",  # type: ignore[arg-type]
            file_path=Path("schema_pb2.py"),
            line_start=1,
            line_end=1,
            depth=2,
        ),
        CodeContextNode(
            identifier="substantive",  # type: ignore[arg-type]
            file_path=Path("real.py"),
            line_start=1,
            line_end=1,
            depth=2,
            finding_evidence_score=0.7,
        ),
    ]

    ranked = _strategy(tmp_path).rank_nodes(nodes)
    order = [n.identifier for n in ranked]

    assert order.index("substantive") < order.index("boilerplate")


def test_drops_overflowing_nodes_under_tight_budget(tmp_path: Path) -> None:
    """When the token budget is small, low-priority nodes appear at the tail (rejected)."""

    _write(tmp_path, Path("a.py"), "x = 1\n" * 200)
    _write(tmp_path, Path("b.py"), "y = 2\n" * 200)

    nodes = [
        CodeContextNode(
            identifier="hi",  # type: ignore[arg-type]
            file_path=Path("a.py"),
            line_start=1,
            line_end=200,
            depth=0,
        ),
        CodeContextNode(
            identifier="lo",  # type: ignore[arg-type]
            file_path=Path("b.py"),
            line_start=1,
            line_end=200,
            depth=3,
        ),
    ]
    strategy = _strategy(
        tmp_path,
        token_budget=200,
        config=BudgetedRankingConfig(small_node_token_threshold=10_000),
    )

    ranked = strategy.rank_nodes(nodes)
    order = [n.identifier for n in ranked]

    # The high-priority node ranks above the low-priority one (which is rejected).
    assert order == ["hi", "lo"]


def test_deterministic_across_repeated_calls(tmp_path: Path) -> None:
    """Repeated calls on identical inputs must return identical orderings."""

    _write(tmp_path, Path("a.py"), "subprocess.run(x)\nval = request.args.get('q')\n")

    nodes = [
        CodeContextNode(
            identifier="sink",  # type: ignore[arg-type]
            file_path=Path("a.py"),
            line_start=1,
            line_end=1,
            depth=1,
        ),
        CodeContextNode(
            identifier="source",  # type: ignore[arg-type]
            file_path=Path("a.py"),
            line_start=2,
            line_end=2,
            depth=1,
        ),
    ]
    strategy = _strategy(tmp_path)

    first = [n.identifier for n in strategy.rank_nodes(nodes)]
    second = [n.identifier for n in strategy.rank_nodes(nodes)]

    assert first == second


def test_default_config_does_not_crash_on_realistic_input(tmp_path: Path) -> None:
    """Smoke test: the default config must produce a non-empty ranking on mixed inputs."""

    _write(tmp_path, Path("app.py"), "import subprocess\nsubprocess.run(cmd)\n")

    nodes = [
        CodeContextNode(
            identifier="root",  # type: ignore[arg-type]
            file_path=Path("app.py"),
            line_start=2,
            line_end=2,
            depth=0,
            finding_evidence_score=0.8,
            taint_score=0.4,
            edge_depths={"FLOWS_TO": 0},
        ),
    ]

    ranked = _strategy(tmp_path).rank_nodes(nodes)

    assert len(ranked) == 1
    assert ranked[0].identifier == "root"
