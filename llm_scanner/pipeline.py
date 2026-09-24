import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import MappingProxyType
from typing import Final

from pydantic import BaseModel, ConfigDict

from clients.analyzers.semgrep import DEFAULT_SEMGREP_CONFIG
from clients.neo4j import Neo4jClient
from models.bandit_report import IssueSeverity
from models.context import FileSpans
from models.edges.analysis import StaticAnalysisReports
from models.nodes.finding import (
    BanditFindingNode,
    DlintFindingNode,
    FindingNode,
    SemgrepFindingNode,
)
from models.scan import ScanReport
from repositories.analyzers.bandit import BanditFindingsRepository
from repositories.analyzers.dlint import DlintFindingsRepository
from repositories.analyzers.semgrep import SemgrepFindingsRepository
from repositories.context import ContextRepository
from repositories.graph import GraphRepository
from services.analyzer.bandit import BanditAnalyzerService
from services.analyzer.base import BaseAnalyzerService
from services.analyzer.dlint import DlintAnalyzerService
from services.analyzer.semgrep import SemgrepAnalyzerService
from services.context_assembler.context_assembler import ContextAssemblerService
from services.cpg_parser.ts_parser.cpg_builder import CPGDirectoryBuilder
from services.llm_review import LLMCodeReviewService, ReviewItem
from services.ranking.ranking import NodeRelevanceRankingService
from services.ranking.strategy_factory import RankingStrategyFactory

_LOGGER: Final[logging.Logger] = logging.getLogger(__name__)

DEFAULT_TOKEN_BUDGET: Final[int] = 4096

_SEVERITY_RANK: Final = MappingProxyType(
    {IssueSeverity.LOW: 0, IssueSeverity.MEDIUM: 1, IssueSeverity.HIGH: 2}
)


class GeneralScannerPipeline(BaseModel):
    """Orchestrates CPG construction, static analysis, and LLM-based code review."""

    src: Path
    neo4j_client: Neo4jClient
    enable_semgrep: bool = False
    semgrep_config: str = DEFAULT_SEMGREP_CONFIG

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def build_cpg(self) -> tuple[list[FindingNode], list[StaticAnalysisReports]]:
        """Build the CPG, run static analyzers, and load everything into Neo4j.

        Returns:
            A tuple of (all_finding_nodes, all_static_analysis_edges) covering
            Bandit and Dlint results, plus Semgrep when ``enable_semgrep`` is set.
        """
        project_root = self.src.resolve()

        graph_repository = GraphRepository(self.neo4j_client)
        ranking_service = NodeRelevanceRankingService(project_root=project_root)
        analyzer_services = self._analyzer_services(project_root, graph_repository)

        nodes, edges = CPGDirectoryBuilder(root=project_root).build()
        code_nodes = list(nodes.values())
        findings: list[FindingNode] = []
        finding_edges: list[StaticAnalysisReports] = []
        with ThreadPoolExecutor(max_workers=len(analyzer_services)) as executor:
            futures = [
                executor.submit(service.get_findings_with_edges, code_nodes)
                for service in analyzer_services
            ]
            for future in futures:
                service_findings, service_edges = future.result()
                findings.extend(service_findings)
                finding_edges.extend(service_edges)
        _nodes = ranking_service.calculate_security_score(code_nodes, findings, finding_edges)
        nodes = {node.identifier: node for node in _nodes}

        graph_repository.load(nodes, edges)
        return findings, finding_edges

    def _analyzer_services(
        self, project_root: Path, graph_repository: GraphRepository
    ) -> list[BaseAnalyzerService]:
        """Return the analyzer services to run, in result order."""

        services: list[BaseAnalyzerService] = [
            DlintAnalyzerService(
                project_root=project_root,
                graph_repository=graph_repository,
                findings_repository=DlintFindingsRepository(client=self.neo4j_client),
            ),
            BanditAnalyzerService(
                project_root=project_root,
                graph_repository=graph_repository,
                findings_repository=BanditFindingsRepository(client=self.neo4j_client),
            ),
        ]
        if self.enable_semgrep:
            services.append(
                SemgrepAnalyzerService(
                    project_root=project_root,
                    graph_repository=graph_repository,
                    findings_repository=SemgrepFindingsRepository(client=self.neo4j_client),
                    config=self.semgrep_config,
                )
            )
        return services

    @classmethod
    def _meets_min_severity(cls, finding: FindingNode, min_severity: IssueSeverity) -> bool:
        """Return True if ``finding`` passes the severity filter (Dlint always passes)."""

        if isinstance(finding, BanditFindingNode | SemgrepFindingNode):
            return _SEVERITY_RANK[finding.severity] >= _SEVERITY_RANK[min_severity]
        return True

    @classmethod
    def _finding_message(cls, finding: FindingNode) -> str:
        """Return the static-tool message passed to the LLM reviewer for ``finding``."""

        location = f"{finding.file}:{finding.line_number}"
        if isinstance(finding, BanditFindingNode):
            return f"Bandit [CWE-{finding.cwe_id}] severity={finding.severity} at {location}"
        if isinstance(finding, SemgrepFindingNode):
            cwe = f" [CWE-{finding.cwe_id}]" if finding.cwe_id is not None else ""
            return f"Semgrep [{finding.rule_id}]{cwe} severity={finding.severity} at {location}"
        if isinstance(finding, DlintFindingNode):
            return f"Dlint [issue={finding.issue_id}] at {location}"
        raise TypeError(f"Unsupported finding type: {type(finding).__name__}")

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
            if assembler.ranking_strategy.requires_taint_scores:
                taint_scores = assembler.fetch_taint_scores([root_id])
                context_nodes = assembler.apply_taint_scores(context_nodes, taint_scores)
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
        token_budget: int = DEFAULT_TOKEN_BUDGET,
        min_severity: IssueSeverity = IssueSeverity.HIGH,
    ) -> ScanReport:
        """Run a full-project scan: build CPG, filter findings, assemble context, review.

        All ``DlintFindingNode`` results are always included; Bandit and Semgrep
        results are filtered by ``min_severity``.

        Args:
            strategy_factory: Factory that produces a ``ContextNodeRankingStrategy``
                given the project root path.
            strategy_name: Human-readable name stored in the report.
            llm_review_service: Service that sends context batches to the LLM.
            max_call_depth: Maximum BFS depth when expanding the code neighborhood.
            token_budget: Approximate token limit for each assembled context.
            min_severity: Minimum Bandit/Semgrep severity to include; Dlint always
                included.

        Returns:
            A ``ScanReport`` with one ``ScanFinding`` per reviewed code node.
        """
        project_root = self.src.resolve()
        all_findings, all_edges = self.build_cpg()

        filtered_findings = [f for f in all_findings if self._meets_min_severity(f, min_severity)]
        kept_ids = {str(f.identifier) for f in filtered_findings}
        filtered_edges = [e for e in all_edges if e.src in kept_ids]

        finding_by_id: dict[str, FindingNode] = {str(f.identifier): f for f in all_findings}
        root_to_messages: dict[str, list[str]] = {}
        for edge in filtered_edges:
            root_to_messages.setdefault(str(edge.dst), []).append(
                self._finding_message(finding_by_id[edge.src])
            )

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
        token_budget: int = DEFAULT_TOKEN_BUDGET,
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
