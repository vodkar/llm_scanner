import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import MappingProxyType
from typing import Final

from pydantic import BaseModel, ConfigDict

from clients.neo4j import Neo4jClient
from models.bandit_report import IssueSeverity
from models.context import FileSpans
from models.edges.analysis import StaticAnalysisReports
from models.nodes.finding import BanditFindingNode, DlintFindingNode, FindingNode
from models.scan import ScanReport
from repositories.analyzers.bandit import BanditFindingsRepository
from repositories.analyzers.dlint import DlintFindingsRepository
from repositories.context import ContextRepository
from repositories.graph import GraphRepository
from services.analyzer.bandit import BanditAnalyzerService
from services.analyzer.dlint import DlintAnalyzerService
from services.context_assembler.context_assembler import ContextAssemblerService
from services.cpg_parser.ts_parser.cpg_builder import CPGDirectoryBuilder
from services.llm_review import LLMCodeReviewService, ReviewItem
from services.ranking.ranking import NodeRelevanceRankingService
from services.ranking.strategy_factory import RankingStrategyFactory

_LOGGER: Final[logging.Logger] = logging.getLogger(__name__)

_SEVERITY_RANK: Final = MappingProxyType(
    {IssueSeverity.LOW: 0, IssueSeverity.MEDIUM: 1, IssueSeverity.HIGH: 2}
)


class GeneralScannerPipeline(BaseModel):
    """Orchestrates CPG construction, static analysis, and LLM-based code review."""

    src: Path
    neo4j_client: Neo4jClient

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def build_cpg(self) -> tuple[list[FindingNode], list[StaticAnalysisReports]]:
        """Build the CPG, run static analyzers, and load everything into Neo4j.

        Returns:
            A tuple of (all_finding_nodes, all_static_analysis_edges) covering
            both Bandit and Dlint results.
        """
        project_root = self.src.resolve()

        graph_repository = GraphRepository(self.neo4j_client)
        dlint_findings_repository = DlintFindingsRepository(client=self.neo4j_client)
        bandit_findings_repository = BanditFindingsRepository(client=self.neo4j_client)

        ranking_service = NodeRelevanceRankingService(project_root=project_root)
        dlint_service = DlintAnalyzerService(
            project_root=project_root,
            graph_repository=graph_repository,
            findings_repository=dlint_findings_repository,
        )
        bandit_service = BanditAnalyzerService(
            project_root=project_root,
            graph_repository=graph_repository,
            findings_repository=bandit_findings_repository,
        )

        nodes, edges = CPGDirectoryBuilder(root=project_root).build()
        code_nodes = list(nodes.values())
        with ThreadPoolExecutor(max_workers=2) as executor:
            dlint_future = executor.submit(dlint_service.get_findings_with_edges, code_nodes)
            bandit_future = executor.submit(bandit_service.get_findings_with_edges, code_nodes)
            dlint_findings, dlint_edges = dlint_future.result()
            bandit_findings, bandit_edges = bandit_future.result()
        _nodes = ranking_service.calculate_security_score(
            code_nodes, dlint_findings + bandit_findings, dlint_edges + bandit_edges
        )
        nodes = {node.identifier: node for node in _nodes}

        graph_repository.load(nodes, edges)
        return dlint_findings + bandit_findings, dlint_edges + bandit_edges

    def _build_context_assembler(
        self,
        strategy_factory: RankingStrategyFactory,
        max_call_depth: int,
        token_budget: int,
    ) -> ContextAssemblerService:
        project_root = self.src.resolve()
        return ContextAssemblerService(
            project_root=project_root,
            context_repository=ContextRepository(client=self.neo4j_client),
            max_call_depth=max_call_depth,
            token_budget=token_budget,
            ranking_strategy=strategy_factory(project_root),
        )

    def _build_review_items(
        self,
        root_ids: list[str],
        assembler: ContextAssemblerService,
        root_to_messages: dict[str, list[str]],
    ) -> list[ReviewItem]:
        items: list[ReviewItem] = []
        project_root = self.src.resolve()
        for root_id in root_ids:
            context_nodes = assembler.fetch_context_nodes_for_root_ids([root_id])
            if not context_nodes:
                _LOGGER.warning("No context nodes found for root_id %s; skipping", root_id)
                continue
            context = assembler.assemble_from_nodes(project_root, context_nodes)
            root_node = next(
                (n for n in context_nodes if str(n.identifier) == root_id), context_nodes[0]
            )
            items.append(
                ReviewItem(
                    root_id=root_id,
                    file_path=project_root / root_node.file_path,
                    line_start=root_node.line_start,
                    line_end=root_node.line_end,
                    context_text=context.context_text,
                    static_tool_messages=root_to_messages.get(root_id, []),
                )
            )
        return items

    def run(
        self,
        strategy_factory: RankingStrategyFactory,
        strategy_name: str,
        llm_review_service: LLMCodeReviewService,
        *,
        max_call_depth: int = 3,
        token_budget: int = 2048,
        min_severity: IssueSeverity = IssueSeverity.HIGH,
    ) -> ScanReport:
        """Run a full-project scan: build CPG, filter findings, assemble context, review.

        All ``DlintFindingNode`` results are always included; ``BanditFindingNode``
        results are filtered by ``min_severity``.

        Args:
            strategy_factory: Factory that produces a ``ContextNodeRankingStrategy``
                given the project root path.
            strategy_name: Human-readable name stored in the report.
            llm_review_service: Service that sends context batches to the LLM.
            max_call_depth: Maximum BFS depth when expanding the code neighborhood.
            token_budget: Approximate token limit for each assembled context.
            min_severity: Minimum Bandit severity to include; Dlint always included.

        Returns:
            A ``ScanReport`` with one ``ScanFinding`` per reviewed code node.
        """
        project_root = self.src.resolve()
        all_findings, all_edges = self.build_cpg()

        min_rank = _SEVERITY_RANK[min_severity]
        filtered_findings = [
            f
            for f in all_findings
            if isinstance(f, DlintFindingNode)
            or (isinstance(f, BanditFindingNode) and _SEVERITY_RANK[f.severity] >= min_rank)
        ]
        kept_ids = {str(f.identifier) for f in filtered_findings}
        filtered_edges = [e for e in all_edges if e.src in kept_ids]

        finding_by_id: dict[str, FindingNode] = {str(f.identifier): f for f in all_findings}
        root_to_messages: dict[str, list[str]] = {}
        for edge in filtered_edges:
            finding = finding_by_id[edge.src]
            if isinstance(finding, BanditFindingNode):
                msg = (
                    f"Bandit [CWE-{finding.cwe_id}] severity={finding.severity}"
                    f" at {finding.file}:{finding.line_number}"
                )
            else:
                assert isinstance(finding, DlintFindingNode)
                msg = f"Dlint [issue={finding.issue_id}] at {finding.file}:{finding.line_number}"
            root_to_messages.setdefault(str(edge.dst), []).append(msg)

        root_ids = list({str(e.dst) for e in filtered_edges})
        _LOGGER.info(
            "Full scan: %d findings → %d unique root code nodes (min severity: %s)",
            len(filtered_findings),
            len(root_ids),
            min_severity,
        )

        assembler = self._build_context_assembler(strategy_factory, max_call_depth, token_budget)
        items = self._build_review_items(root_ids, assembler, root_to_messages)
        findings = llm_review_service.review(items)

        return ScanReport(
            src=project_root,
            mode="full",
            strategy=strategy_name,
            findings=findings,
            total_contexts_scanned=len(items),
        )

    def run_diff(
        self,
        file_spans: list[FileSpans],
        strategy_factory: RankingStrategyFactory,
        strategy_name: str,
        llm_review_service: LLMCodeReviewService,
        *,
        max_call_depth: int = 3,
        token_budget: int = 2048,
    ) -> ScanReport:
        """Run a diff-mode scan: build CPG, resolve spans to nodes, review.

        Args:
            file_spans: Changed file spans parsed from a git unified diff.
            strategy_factory: Factory producing a ``ContextNodeRankingStrategy``.
            strategy_name: Human-readable name stored in the report.
            llm_review_service: Service that sends context batches to the LLM.
            max_call_depth: Maximum BFS depth when expanding the code neighborhood.
            token_budget: Approximate token limit for each assembled context.

        Returns:
            A ``ScanReport`` with one ``ScanFinding`` per reviewed code node.
        """
        project_root = self.src.resolve()
        self.build_cpg()

        assembler = self._build_context_assembler(strategy_factory, max_call_depth, token_budget)
        root_ids = assembler.fetch_root_ids_for_spans(file_spans)
        _LOGGER.info(
            "Diff scan: %d root code nodes from %d file spans", len(root_ids), len(file_spans)
        )

        items = self._build_review_items(root_ids, assembler, {})
        findings = llm_review_service.review(items)

        return ScanReport(
            src=project_root,
            mode="diff",
            strategy=strategy_name,
            findings=findings,
            total_contexts_scanned=len(items),
        )
