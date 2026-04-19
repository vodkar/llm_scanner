"""Tests for the edge-type-aware CPGStructuralRankingStrategy."""

from __future__ import annotations

from pathlib import Path
from typing import Final

import pytest

from models.base import NodeID
from models.context import CodeContextNode
from services.context_assembler.cpg_structural_ranking import CPGStructuralRankingStrategy
from services.context_assembler.ranking_config import RankingCoefficients

PROJECT_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
CPG_STRUCTURAL_YAML: Final[Path] = (
    PROJECT_ROOT / "config" / "ranking_coefficients_cpg_structural.yaml"
)


@pytest.fixture(autouse=True)
def clear_neo4j_database() -> None:
    """Override the global Neo4j autouse fixture for pure unit tests."""

    return None


def _make_node(
    *,
    identifier: str,
    depth: int,
    edge_depths: dict[str, int] | None,
    snippet_line: str,
    tmp_path: Path,
) -> CodeContextNode:
    source_file = tmp_path / f"{identifier}.py"
    source_file.write_text(snippet_line + "\n", encoding="utf-8")
    return CodeContextNode(
        identifier=NodeID(identifier),
        node_kind="FunctionNode",
        name=identifier,
        file_path=Path(f"{identifier}.py"),
        line_start=1,
        line_end=1,
        depth=depth,
        edge_depths=edge_depths,
    )


def test_requires_edge_paths_flag_is_true(tmp_path: Path) -> None:
    """The strategy must declare it requires per-edge-type depth data."""

    strategy = CPGStructuralRankingStrategy(project_root=tmp_path)

    assert strategy.requires_edge_paths is True


def test_flows_to_node_outranks_contains_node_at_same_depth(tmp_path: Path) -> None:
    """A node reached via FLOWS_TO must score above one reached via CONTAINS at same depth."""

    coefficients = RankingCoefficients.from_yaml(CPG_STRUCTURAL_YAML)

    flows_node = _make_node(
        identifier="flows",
        depth=2,
        edge_depths={"FLOWS_TO": 2},
        snippet_line="def consume(value): return value",
        tmp_path=tmp_path,
    )
    contains_node = _make_node(
        identifier="contains",
        depth=2,
        edge_depths={"CONTAINS": 2},
        snippet_line="def contained(value): return value",
        tmp_path=tmp_path,
    )

    strategy = CPGStructuralRankingStrategy(
        project_root=tmp_path, coefficients=coefficients
    )
    ranked = strategy.rank_context_nodes([flows_node, contains_node])

    scored_by_id = {str(node.identifier): node for node in ranked}
    assert (
        scored_by_id["flows"].context_score > scored_by_id["contains"].context_score
    )


def test_unsanitized_source_sink_path_receives_bonus(tmp_path: Path) -> None:
    """A node on an unsanitized FLOWS_TO source-sink path gets a security bonus."""

    coefficients = RankingCoefficients.from_yaml(CPG_STRUCTURAL_YAML)

    sink_node = _make_node(
        identifier="sink",
        depth=0,
        edge_depths={"FLOWS_TO": 0},
        snippet_line="subprocess.run(command, shell=True)",
        tmp_path=tmp_path,
    )
    mid_node = _make_node(
        identifier="mid",
        depth=1,
        edge_depths={"FLOWS_TO": 1},
        snippet_line="command = build_command(user_value)",
        tmp_path=tmp_path,
    )
    source_node = _make_node(
        identifier="source",
        depth=2,
        edge_depths={"FLOWS_TO": 2},
        snippet_line="user_value = request.args.get('q')",
        tmp_path=tmp_path,
    )

    strategy = CPGStructuralRankingStrategy(
        project_root=tmp_path, coefficients=coefficients
    )
    ranked = strategy.rank_context_nodes([sink_node, mid_node, source_node])

    scored_by_id = {str(node.identifier): node for node in ranked}
    assert scored_by_id["mid"].security_path_score > 0.0


def test_sanitized_path_receives_damped_bonus(tmp_path: Path) -> None:
    """A sanitized source-sink path produces a smaller bonus than an unsanitized one."""

    coefficients = RankingCoefficients.from_yaml(CPG_STRUCTURAL_YAML)

    unsanitized_mid = _make_node(
        identifier="mid",
        depth=1,
        edge_depths={"FLOWS_TO": 1},
        snippet_line="command = build_command(user_value)",
        tmp_path=tmp_path,
    )
    sanitized_mid = _make_node(
        identifier="mid_safe",
        depth=1,
        edge_depths={"FLOWS_TO": 1, "SANITIZED_BY": 1},
        snippet_line="command = build_command(user_value)",
        tmp_path=tmp_path,
    )
    sink_node = _make_node(
        identifier="sink",
        depth=0,
        edge_depths={"FLOWS_TO": 0},
        snippet_line="subprocess.run(command, shell=True)",
        tmp_path=tmp_path,
    )
    source_node = _make_node(
        identifier="source",
        depth=2,
        edge_depths={"FLOWS_TO": 2},
        snippet_line="user_value = request.args.get('q')",
        tmp_path=tmp_path,
    )

    strategy = CPGStructuralRankingStrategy(
        project_root=tmp_path, coefficients=coefficients
    )
    ranked_unsanitized = strategy.rank_context_nodes(
        [sink_node, unsanitized_mid, source_node]
    )
    ranked_sanitized = strategy.rank_context_nodes(
        [sink_node, sanitized_mid, source_node]
    )

    unsanitized_by_id = {str(node.identifier): node for node in ranked_unsanitized}
    sanitized_by_id = {str(node.identifier): node for node in ranked_sanitized}
    assert (
        unsanitized_by_id["mid"].security_path_score
        > sanitized_by_id["mid_safe"].security_path_score
    )


def test_missing_edge_depths_falls_back_to_hop_decay(tmp_path: Path) -> None:
    """Nodes without edge_depths must gracefully fall back to generic hop decay."""

    coefficients = RankingCoefficients.from_yaml(CPG_STRUCTURAL_YAML)

    fallback_node = _make_node(
        identifier="fallback",
        depth=3,
        edge_depths=None,
        snippet_line="def helper(): pass",
        tmp_path=tmp_path,
    )

    strategy = CPGStructuralRankingStrategy(
        project_root=tmp_path, coefficients=coefficients
    )
    ranked = strategy.rank_context_nodes([fallback_node])

    assert ranked[0].context_score > 0.0
