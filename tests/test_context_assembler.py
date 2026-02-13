"""Integration tests for ContextAssemblerService."""

from __future__ import annotations

from pathlib import Path
from typing import Final

from clients.neo4j import Neo4jClient
from models.bandit_report import IssueSeverity
from models.base import NodeID
from models.edges.analysis import StaticAnalysisReports
from models.edges.call_graph import CallGraphCalls
from models.nodes.code import FunctionNode
from models.nodes.finding import BanditFindingNode
from repositories.analyzers.bandit import BanditFindingsRepository
from repositories.analyzers.dlint import DlintFindingsRepository
from repositories.context import ContextRepository
from repositories.graph import GraphRepository
from services.context_assembler import ContextAssemblerService
from tests.consts import PROJECT_ROOT
from tests.utils import symbol_byte_index

CALLS_FILE: Final[Path] = Path("tests/data/calls/function_calls.py")


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

    edges: list[CallGraphCalls] = [
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
        return text.count("Node:") + 1

    service = ContextAssemblerService(
        project_root=PROJECT_ROOT,
        bandit_repository=bandit_repo,
        dlint_repository=dlint_repo,
        context_repository=ContextRepository(client=neo4j_client),
        max_call_depth=3,
        token_budget=2,
        token_estimator=estimator,
    )

    assembly = service.assemble()

    assert len(assembly.findings) == 1
    context = assembly.findings[0]
    assert context.finding_id == str(finding.identifier)
    assert context.description == "cwe=79 severity=HIGH"
    assert "def foo" in context.context_text
    assert "def bar" not in context.context_text
    assert context.token_count == 2


def test_context_assembler_includes_code_nodes(neo4j_client: Neo4jClient) -> None:
    """Ensure BFS nodes are collected for findings."""

    foo_id, bar_id = _build_call_graph(neo4j_client)

    finding = BanditFindingNode(
        file=CALLS_FILE,
        line_number=6,
        cwe_id=89,
        severity=IssueSeverity.MEDIUM,
    )

    bandit_repo = BanditFindingsRepository(client=neo4j_client)
    dlint_repo = DlintFindingsRepository(client=neo4j_client)
    bandit_repo.insert_nodes([finding])
    bandit_repo.insert_edges([StaticAnalysisReports(src=str(finding.identifier), dst=foo_id)])

    service = ContextAssemblerService(
        project_root=PROJECT_ROOT,
        bandit_repository=bandit_repo,
        dlint_repository=dlint_repo,
        context_repository=ContextRepository(client=neo4j_client),
        max_call_depth=3,
        token_budget=500,
    )

    assembly = service.assemble()

    assert len(assembly.findings) == 1
    node_ids = {node.node_id for node in assembly.findings[0].nodes}
    assert str(foo_id) in node_ids
    assert str(bar_id) in node_ids
