"""Integration tests for ContextAssemblerService."""

from __future__ import annotations

from pathlib import Path
from typing import Final

from clients.neo4j import Neo4jClient
from models.bandit_report import IssueSeverity
from models.base import NodeID
from models.context import CodeContextNode
from models.edges import RelationshipBase
from models.edges.analysis import StaticAnalysisReports
from models.edges.call_graph import CallGraphCalls
from models.nodes.code import FunctionNode
from models.nodes.finding import BanditFindingNode
from repositories.analyzers.bandit import BanditFindingsRepository
from repositories.analyzers.dlint import DlintFindingsRepository
from repositories.context import ContextRepository
from repositories.graph import GraphRepository
from services.context_assembler.context_assembler import ContextAssemblerService
from tests.consts import PROJECT_ROOT
from tests.utils import symbol_byte_index

CALLS_FILE: Final[Path] = Path("tests/data/calls/function_calls.py")


class TestableContextAssemblerService(ContextAssemblerService):
    """Expose internal selection logic for test assertions."""

    def select_full_context_node_id(self, rows: list[CodeContextNode]) -> str | None:
        """Proxy to protected full-node selection logic."""

        return self._select_full_context_node_id(rows)


def _build_call_graph(neo4j_client: Neo4jClient) -> tuple[NodeID, NodeID]:
    """Load a small call graph into Neo4j.

    Args:
        neo4j_client: Neo4j client fixture.

    Returns:
        Tuple containing function identifiers for foo and bar.
    """

    data: bytes = (PROJECT_ROOT / CALLS_FILE).read_bytes()
    foo_sb: int = symbol_byte_index(data, b"def foo")
    bar_sb: int = symbol_byte_index(data, b"def bar")

    foo_id: NodeID = NodeID.create("function", "foo", str(CALLS_FILE), foo_sb)
    bar_id: NodeID = NodeID.create("function", "bar", str(CALLS_FILE), bar_sb)

    foo_node: FunctionNode = FunctionNode(
        identifier=foo_id,
        file_path=CALLS_FILE,
        line_start=5,
        line_end=7,
        token_count=0,
        name="foo",
    )
    bar_node: FunctionNode = FunctionNode(
        identifier=bar_id,
        file_path=CALLS_FILE,
        line_start=1,
        line_end=2,
        token_count=0,
        name="bar",
    )

    edges: list[RelationshipBase] = [
        CallGraphCalls(src=foo_id, dst=bar_id, is_direct=True, call_depth=1)
    ]
    GraphRepository(neo4j_client).load({foo_id: foo_node, bar_id: bar_node}, edges)
    return foo_id, bar_id


def test_context_assembler_renders_snippet_and_respects_budget(
    neo4j_client: Neo4jClient,
) -> None:
    """Validate context rendering and token budget enforcement."""

    foo_id, _bar_id = _build_call_graph(neo4j_client)

    finding = BanditFindingNode(
        file=CALLS_FILE,
        line_number=6,
        cwe_id=79,
        severity=IssueSeverity.HIGH,
    )

    bandit_repo = BanditFindingsRepository(client=neo4j_client)
    dlint_repo = DlintFindingsRepository(client=neo4j_client)
    bandit_repo.insert_nodes([finding])
    bandit_repo.insert_edges([StaticAnalysisReports(src=str(finding.identifier), dst=foo_id)])

    def estimator(text: str) -> int:
        return max(1, text.count("\n") + 1)

    service = ContextAssemblerService(
        project_root=PROJECT_ROOT,
        bandit_repository=bandit_repo,
        dlint_repository=dlint_repo,
        context_repository=ContextRepository(client=neo4j_client),
        max_call_depth=3,
        token_budget=6,
        token_estimator=estimator,
    )

    assembly = service.assemble()

    assert len(assembly.contexts) == 1
    context = assembly.contexts[0]
    assert context.description == "cwe=79 severity=HIGH"
    assert "def foo" in context.context_text
    assert "Node:" not in context.context_text
    assert "def bar" in context.context_text
    assert context.token_count == 5


def test_context_assembler_prefers_full_enclosing_node(neo4j_client: Neo4jClient) -> None:
    """Ensure full enclosing nodes are preferred over single-line nodes."""

    bandit_repo = BanditFindingsRepository(client=neo4j_client)
    dlint_repo = DlintFindingsRepository(client=neo4j_client)
    service = TestableContextAssemblerService(
        project_root=PROJECT_ROOT,
        bandit_repository=bandit_repo,
        dlint_repository=dlint_repo,
        context_repository=ContextRepository(client=neo4j_client),
        max_call_depth=3,
        token_budget=500,
    )

    selected_node_id = service.select_full_context_node_id(
        [
            CodeContextNode(
                node_id=NodeID("call-node"),
                node_kind="CallNode",
                name=None,
                file_path=CALLS_FILE,
                line_start=12,
                line_end=12,
                depth=0,
            ),
            CodeContextNode(
                node_id=NodeID("function-node"),
                node_kind="FunctionNode",
                name=None,
                file_path=CALLS_FILE,
                line_start=8,
                line_end=32,
                depth=0,
            ),
        ]
    )

    assert selected_node_id == "function-node"


def test_assemble_for_vulnerability_span_filters_before_context(
    neo4j_client: Neo4jClient,
) -> None:
    """Ensure span-filtered assembly returns associated and limited non-associated contexts."""

    foo_id, bar_id = _build_call_graph(neo4j_client)

    associated_finding = BanditFindingNode(
        file=CALLS_FILE,
        line_number=6,
        cwe_id=79,
        severity=IssueSeverity.HIGH,
    )
    non_associated_finding = BanditFindingNode(
        file=CALLS_FILE,
        line_number=1,
        cwe_id=89,
        severity=IssueSeverity.MEDIUM,
    )

    bandit_repo = BanditFindingsRepository(client=neo4j_client)
    dlint_repo = DlintFindingsRepository(client=neo4j_client)
    bandit_repo.insert_nodes([associated_finding, non_associated_finding])
    bandit_repo.insert_edges(
        [
            StaticAnalysisReports(src=str(associated_finding.identifier), dst=foo_id),
            StaticAnalysisReports(src=str(non_associated_finding.identifier), dst=bar_id),
        ]
    )

    service = ContextAssemblerService(
        project_root=PROJECT_ROOT,
        bandit_repository=bandit_repo,
        dlint_repository=dlint_repo,
        context_repository=ContextRepository(client=neo4j_client),
        max_call_depth=3,
        token_budget=500,
    )

    associated, non_associated = service.assemble_for_vulnerability_span(
        target_file=CALLS_FILE,
        start_line=5,
        end_line=7,
        non_associated_limit=1,
    )

    assert len(associated.contexts) == 1
    assert "def foo" in associated.contexts[0].context_text

    assert len(non_associated.contexts) == 1
