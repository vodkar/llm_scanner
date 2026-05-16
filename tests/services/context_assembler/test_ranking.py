"""Unit tests for context ranking passes."""

from pathlib import Path

import pytest

from models.bandit_report import IssueSeverity
from models.base import NodeID
from models.context import CodeContextNode
from models.edges.analysis import StaticAnalysisReports
from models.nodes.code import FunctionNode
from models.nodes.finding import BanditFindingNode
from services.ranking.ranking import (
    DepthRepeatsContextNodeRankingStrategy,
    DummyNodeRankingStrategy,
    MultiplicativeBoostNodeRankingStrategy,
    NodeRelevanceRankingService,
    RandomNodeRankingStrategy,
)
from services.snippet_reader import SnippetReaderService


@pytest.fixture(autouse=True)
def clear_neo4j_database() -> None:
    """Override the global Neo4j autouse fixture for pure unit tests."""

    return None


def test_snippet_reader_reads_expected_line_range(tmp_path: Path) -> None:
    """Snippet reader should return the requested file slice."""

    source_file = tmp_path / "pkg" / "sample.py"
    source_file.parent.mkdir(parents=True)
    source_file.write_text("line1\nline2\nline3\nline4\n", encoding="utf-8")

    reader = SnippetReaderService(project_root=tmp_path)

    assert reader.read_snippet(Path("pkg/sample.py"), 2, 3) == "line2\nline3"


def test_calculate_security_score_matches_findings_via_report_edges(tmp_path: Path) -> None:
    """Security scoring should attach direct findings through REPORTS edges."""

    source_file = tmp_path / "pkg" / "sample.py"
    source_file.parent.mkdir(parents=True)
    source_file.write_text(
        "def handler():\n    render_template('index.html')\n\ndef helper():\n    pass\n",
        encoding="utf-8",
    )

    reported_node = FunctionNode(
        identifier=NodeID("function:reported"),
        name="handler",
        file_path=Path("pkg/sample.py"),
        line_start=1,
        line_end=2,
    )
    helper_node = FunctionNode(
        identifier=NodeID("function:helper"),
        name="helper",
        file_path=Path("pkg/sample.py"),
        line_start=4,
        line_end=5,
    )
    finding = BanditFindingNode(
        file=Path("pkg/sample.py"),
        line_number=2,
        cwe_id=79,
        severity=IssueSeverity.HIGH,
    )
    finding_edge = StaticAnalysisReports(
        src=str(finding.identifier),
        dst=reported_node.identifier,
    )

    scored_nodes = NodeRelevanceRankingService(project_root=tmp_path).calculate_security_score(
        nodes=[helper_node, reported_node],
        finding_nodes=[finding],
        finding_edges=[finding_edge],
    )

    scored_by_id = {node.identifier: node for node in scored_nodes}
    assert scored_by_id[reported_node.identifier].finding_evidence_score > 0.0
    assert scored_by_id[reported_node.identifier].security_path_score > 0.0
    assert scored_by_id[helper_node.identifier].finding_evidence_score == 0.0


def test_rank_context_nodes_calculates_context_score_without_finding_inputs(
    tmp_path: Path,
) -> None:
    """Context scoring should depend only on the context neighborhood itself."""

    source_file = tmp_path / "pkg" / "sample.py"
    source_file.parent.mkdir(parents=True)
    source_file.write_text(
        "def anchor():\n    pass\n\nclass Helper:\n    pass\n",
        encoding="utf-8",
    )

    anchor_node = CodeContextNode(
        identifier=NodeID("function:anchor"),
        node_kind="FunctionNode",
        name="anchor",
        file_path=Path("pkg/sample.py"),
        line_start=1,
        line_end=2,
        depth=0,
    )
    far_node = CodeContextNode(
        identifier=NodeID("class:helper"),
        node_kind="ClassNode",
        name="Helper",
        file_path=Path("pkg/other.py"),
        line_start=1,
        line_end=2,
        depth=3,
    )

    scored_nodes = NodeRelevanceRankingService(project_root=tmp_path).rank_context_nodes(
        nodes=[far_node, anchor_node]
    )

    scored_by_id = {node.identifier: node for node in scored_nodes}
    assert (
        scored_by_id[anchor_node.identifier].context_score
        > scored_by_id[far_node.identifier].context_score
    )


def test_rank_context_nodes_aggregates_duplicates_and_preserves_shallowest_depth(
    tmp_path: Path,
) -> None:
    """Duplicate context nodes should become one scored node with a stable depth."""

    source_file = tmp_path / "pkg" / "sample.py"
    source_file.parent.mkdir(parents=True)
    source_file.write_text("def anchor():\n    pass\n", encoding="utf-8")

    deep_node = CodeContextNode(
        identifier=NodeID("function:anchor"),
        node_kind="FunctionNode",
        name="anchor",
        file_path=Path("pkg/sample.py"),
        line_start=1,
        line_end=2,
        depth=2,
    )
    shallow_node = CodeContextNode(
        identifier=NodeID("function:anchor"),
        node_kind="FunctionNode",
        name="anchor",
        file_path=Path("pkg/sample.py"),
        line_start=1,
        line_end=2,
        depth=0,
    )

    scored_nodes = NodeRelevanceRankingService(project_root=tmp_path).rank_context_nodes(
        nodes=[deep_node, shallow_node]
    )

    assert len(scored_nodes) == 1
    assert scored_nodes[0].identifier == shallow_node.identifier
    assert scored_nodes[0].depth == 0
    assert scored_nodes[0].repeats == 1


def test_calculate_final_score_combines_components_and_sorts(tmp_path: Path) -> None:
    """Final score calculation should combine split score fields and sort descending."""

    high_security_node = CodeContextNode(
        identifier=NodeID("function:high-security"),
        node_kind="FunctionNode",
        name="high_security",
        file_path=Path("pkg/a.py"),
        line_start=1,
        line_end=2,
        depth=1,
        finding_evidence_score=1.0,
        security_path_score=1.0,
        context_score=0.4,
    )
    high_context_node = CodeContextNode(
        identifier=NodeID("function:high-context"),
        node_kind="FunctionNode",
        name="high_context",
        file_path=Path("pkg/a.py"),
        line_start=3,
        line_end=4,
        depth=0,
        finding_evidence_score=0.0,
        security_path_score=0.0,
        context_score=1.0,
    )

    final_nodes = NodeRelevanceRankingService(project_root=tmp_path).calculate_final_score(
        nodes=[high_context_node, high_security_node]
    )

    scored_by_id = {node.identifier: node for node in final_nodes}
    assert (
        scored_by_id[high_security_node.identifier].score
        > scored_by_id[high_context_node.identifier].score
    )
    assert all(0.0 <= node.score <= 1.0 for node in final_nodes)


def test_current_strategy_ranks_root_nodes_before_higher_scoring_non_root_nodes(
    tmp_path: Path,
) -> None:
    """The default strategy should preserve root-first ordering."""

    source_file = tmp_path / "pkg" / "sample.py"
    source_file.parent.mkdir(parents=True)
    source_file.write_text(
        "def root_node():\n    return 1\n\ndef risky_node():\n    return 2\n",
        encoding="utf-8",
    )

    root_node = CodeContextNode(
        identifier=NodeID("function:root"),
        node_kind="FunctionNode",
        name="root_node",
        file_path=Path("pkg/sample.py"),
        line_start=1,
        line_end=2,
        depth=0,
        security_path_score=0.0,
    )
    non_root_node = CodeContextNode(
        identifier=NodeID("function:risky"),
        node_kind="FunctionNode",
        name="risky_node",
        file_path=Path("pkg/sample.py"),
        line_start=4,
        line_end=5,
        depth=2,
        finding_evidence_score=1.0,
        security_path_score=1.0,
    )

    ranked_nodes = NodeRelevanceRankingService(project_root=tmp_path).rank_nodes(
        [non_root_node, root_node]
    )

    assert [node.identifier for node in ranked_nodes] == [
        root_node.identifier,
        non_root_node.identifier,
    ]


def test_depth_repeats_context_strategy_orders_by_depth_then_repeats(tmp_path: Path) -> None:
    """Depth and repeat count should drive ordering for the depth strategy."""

    source_file = tmp_path / "pkg" / "sample.py"
    source_file.parent.mkdir(parents=True)
    source_file.write_text(
        "def repeated():\n    pass\n\ndef single():\n    pass\n",
        encoding="utf-8",
    )

    repeated_deep_node = CodeContextNode(
        identifier=NodeID("function:repeated"),
        node_kind="FunctionNode",
        name="repeated",
        file_path=Path("pkg/sample.py"),
        line_start=1,
        line_end=2,
        depth=2,
    )
    repeated_shallow_node = CodeContextNode(
        identifier=NodeID("function:repeated"),
        node_kind="FunctionNode",
        name="repeated",
        file_path=Path("pkg/sample.py"),
        line_start=1,
        line_end=2,
        depth=1,
    )
    single_node = CodeContextNode(
        identifier=NodeID("function:single"),
        node_kind="FunctionNode",
        name="single",
        file_path=Path("pkg/sample.py"),
        line_start=4,
        line_end=5,
        depth=1,
    )

    ranked_nodes = DepthRepeatsContextNodeRankingStrategy(project_root=tmp_path).rank_nodes(
        [single_node, repeated_deep_node, repeated_shallow_node]
    )

    assert [node.identifier for node in ranked_nodes] == [
        repeated_shallow_node.identifier,
        single_node.identifier,
    ]
    assert ranked_nodes[0].repeats == 1


def test_random_strategy_keeps_root_nodes_first(tmp_path: Path) -> None:
    """Random strategy should shuffle within root grouping only."""

    source_file = tmp_path / "pkg" / "sample.py"
    source_file.parent.mkdir(parents=True)
    source_file.write_text(
        "def root_a():\n    pass\n\ndef root_b():\n    "
        "pass\n\ndef child_a():\n    pass\n\ndef child_b():\n    pass\n",
        encoding="utf-8",
    )

    root_a = CodeContextNode(
        identifier=NodeID("function:root-a"),
        node_kind="FunctionNode",
        name="root_a",
        file_path=Path("pkg/sample.py"),
        line_start=1,
        line_end=2,
        depth=0,
    )
    root_b = CodeContextNode(
        identifier=NodeID("function:root-b"),
        node_kind="FunctionNode",
        name="root_b",
        file_path=Path("pkg/sample.py"),
        line_start=4,
        line_end=5,
        depth=0,
    )
    child_a = CodeContextNode(
        identifier=NodeID("function:child-a"),
        node_kind="FunctionNode",
        name="child_a",
        file_path=Path("pkg/sample.py"),
        line_start=7,
        line_end=8,
        depth=1,
    )
    child_b = CodeContextNode(
        identifier=NodeID("function:child-b"),
        node_kind="FunctionNode",
        name="child_b",
        file_path=Path("pkg/sample.py"),
        line_start=10,
        line_end=11,
        depth=1,
    )

    ranked_nodes = RandomNodeRankingStrategy(project_root=tmp_path, random_seed=7).rank_nodes(
        [root_a, root_b, child_a, child_b]
    )

    assert [node.depth for node in ranked_nodes[:2]] == [0, 0]
    assert sorted(node.identifier for node in ranked_nodes[:2]) == sorted(
        [root_a.identifier, root_b.identifier]
    )
    assert sorted(node.identifier for node in ranked_nodes[2:]) == sorted(
        [child_a.identifier, child_b.identifier]
    )


def test_dummy_strategy_returns_same_list_instance() -> None:
    """Dummy strategy should be a no-op."""

    nodes = [
        CodeContextNode(
            identifier=NodeID("function:noop"),
            node_kind="FunctionNode",
            name="noop",
            file_path=Path("pkg/a.py"),
            line_start=1,
            line_end=2,
            depth=0,
        )
    ]

    assert DummyNodeRankingStrategy().rank_nodes(nodes) is nodes


def test_current_strategy_score_only_sort_no_tier_promotion() -> None:
    """Sort tuple is (depth!=0, -score, depth). No binary tier pre-sort.

    Verifies that a low-final-score node carrying a strong security signal (fe+sp>0.5)
    no longer leapfrogs a high-final-score non-security node — the behavior the old
    tier pre-sort (now removed) was forcing.
    """

    anchor = CodeContextNode.model_construct(
        identifier=NodeID("anchor"),
        node_kind="FunctionNode",
        name="anchor",
        file_path=Path("a.py"),
        line_start=1,
        line_end=2,
        depth=0,
        score=0.30,
        finding_evidence_score=0.0,
        security_path_score=0.0,
    )
    high_score_neighbor = CodeContextNode.model_construct(
        identifier=NodeID("hi"),
        node_kind="FunctionNode",
        name="hi",
        file_path=Path("a.py"),
        line_start=3,
        line_end=4,
        depth=1,
        score=0.80,
        finding_evidence_score=0.0,
        security_path_score=0.0,
    )
    low_score_security_node = CodeContextNode.model_construct(
        identifier=NodeID("lo"),
        node_kind="FunctionNode",
        name="lo",
        file_path=Path("b.py"),
        line_start=1,
        line_end=2,
        depth=1,
        score=0.20,
        finding_evidence_score=0.5,
        security_path_score=0.4,
    )

    sort_key = lambda item: (item.depth != 0, -item.score, item.depth)  # noqa: E731
    sorted_nodes = sorted([low_score_security_node, high_score_neighbor, anchor], key=sort_key)

    assert [n.identifier for n in sorted_nodes] == [
        anchor.identifier,
        high_score_neighbor.identifier,
        low_score_security_node.identifier,
    ]


def test_multiplicative_boost_amplifies_security_relevant_nodes(tmp_path: Path) -> None:
    """Multiplicative boost should give higher final score to security-relevant nodes."""

    source_file = tmp_path / "pkg" / "sample.py"
    source_file.parent.mkdir(parents=True)
    source_file.write_text(
        "def plain():\n    pass\n\ndef boosted():\n    pass\n",
        encoding="utf-8",
    )

    plain_node = CodeContextNode(
        identifier=NodeID("function:plain"),
        node_kind="FunctionNode",
        name="plain",
        file_path=Path("pkg/sample.py"),
        line_start=1,
        line_end=2,
        depth=1,
        finding_evidence_score=0.0,
        security_path_score=0.0,
        context_score=0.6,
    )
    boosted_node = CodeContextNode(
        identifier=NodeID("function:boosted"),
        node_kind="FunctionNode",
        name="boosted",
        file_path=Path("pkg/sample.py"),
        line_start=4,
        line_end=5,
        depth=1,
        finding_evidence_score=0.3,
        security_path_score=0.4,
        context_score=0.6,
    )

    strategy = MultiplicativeBoostNodeRankingStrategy(project_root=tmp_path)
    scored_nodes = strategy.calculate_final_score([plain_node, boosted_node])

    scored_by_id = {node.identifier: node for node in scored_nodes}
    assert scored_by_id[boosted_node.identifier].score > scored_by_id[plain_node.identifier].score
    assert scored_by_id[plain_node.identifier].score == pytest.approx(0.6, abs=0.01)


def test_default_coefficients_match_current_yaml_byte_exact(tmp_path: Path) -> None:
    """Scores with default coefficients must equal scores loaded from current.yaml."""

    from services.ranking.ranking_config import RankingCoefficients

    project_root = Path(__file__).resolve().parents[3]
    current_yaml = project_root / "config" / "ranking_coefficients_current.yaml"
    yaml_coefficients = RankingCoefficients.from_yaml(current_yaml)

    source_file = tmp_path / "pkg" / "sample.py"
    source_file.parent.mkdir(parents=True)
    source_file.write_text(
        "def handler():\n    render_template('index.html')\n\ndef helper():\n    pass\n",
        encoding="utf-8",
    )

    reported_node = FunctionNode(
        identifier=NodeID("function:reported"),
        name="handler",
        file_path=Path("pkg/sample.py"),
        line_start=1,
        line_end=2,
    )
    finding = BanditFindingNode(
        file=Path("pkg/sample.py"),
        line_number=2,
        cwe_id=79,
        severity=IssueSeverity.HIGH,
    )
    finding_edge = StaticAnalysisReports(
        src=str(finding.identifier),
        dst=reported_node.identifier,
    )

    default_service = NodeRelevanceRankingService(project_root=tmp_path)
    yaml_service = NodeRelevanceRankingService(
        project_root=tmp_path, coefficients=yaml_coefficients
    )

    default_scored = default_service.calculate_security_score(
        nodes=[reported_node], finding_nodes=[finding], finding_edges=[finding_edge]
    )
    yaml_scored = yaml_service.calculate_security_score(
        nodes=[reported_node], finding_nodes=[finding], finding_edges=[finding_edge]
    )

    assert default_scored[0].finding_evidence_score == yaml_scored[0].finding_evidence_score
    assert default_scored[0].security_path_score == yaml_scored[0].security_path_score

    context_nodes = [
        CodeContextNode(
            identifier=NodeID("function:anchor"),
            node_kind="FunctionNode",
            name="anchor",
            file_path=Path("pkg/sample.py"),
            line_start=1,
            line_end=2,
            depth=0,
        ),
        CodeContextNode(
            identifier=NodeID("class:helper"),
            node_kind="ClassNode",
            name="Helper",
            file_path=Path("pkg/other.py"),
            line_start=1,
            line_end=2,
            depth=3,
        ),
    ]

    default_context = default_service.rank_context_nodes(context_nodes)
    yaml_context = yaml_service.rank_context_nodes(context_nodes)

    for default_node, yaml_node in zip(default_context, yaml_context, strict=True):
        assert default_node.context_score == yaml_node.context_score
