import logging
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import MappingProxyType
from typing import Final

from pydantic import BaseModel, ConfigDict

from clients.analyzers.semgrep import DEFAULT_SEMGREP_CONFIG
from clients.neo4j import Neo4jClient
from models.bandit_report import IssueSeverity
from models.context import FileSpans, RootContext
from models.edges.analysis import StaticAnalysisReports
from models.nodes.finding import (
    BanditFindingNode,
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
from services.benchmark.static_findings import attach_findings
from services.context_assembler.context_assembler import ContextAssemblerService
from services.cpg_parser.ts_parser.cpg_builder import CPGDirectoryBuilder
from services.llm_review import LLMCodeReviewService, ReviewItem, ReviewRoot
from services.ranking.ranking import NodeRelevanceRankingService
from services.ranking.strategy_factory import RankingStrategyFactory

_LOGGER: Final[logging.Logger] = logging.getLogger(__name__)

DEFAULT_TOKEN_BUDGET: Final[int] = 4096
DIFF_ROOT_TOKEN_SHARE: Final[float] = 0.5
"""Share of the diff-mode token budget given to changed code; the rest is left for context."""

_SEVERITY_RANK: Final = MappingProxyType(
    {IssueSeverity.LOW: 0, IssueSeverity.MEDIUM: 1, IssueSeverity.HIGH: 2}
)


def _changed_lines(root: RootContext, changed_spans: Sequence[FileSpans]) -> tuple[int, int]:
    """Return the root's line range narrowed to the changed lines it contains.

    Code scanning attributes an alert to a pull request only when its start line
    was changed, so a root rendered with unchanged enclosing lines (e.g. its
    ``def``) must start at its first changed line.
    """
    overlaps: list[tuple[int, int]] = [
        (max(start, root.line_start), min(end, root.line_end))
        for spans in changed_spans
        if spans.file_path == root.file_path
        for start, end in spans.line_spans
        if start <= root.line_end and end >= root.line_start
    ]
    if not overlaps:
        return root.line_start, root.line_end
    return min(start for start, _ in overlaps), max(end for _, end in overlaps)


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
        root_id_groups: list[list[str]],
        assembler: ContextAssemblerService,
        static_findings: Sequence[FindingNode],
        changed_spans: Sequence[FileSpans] = (),
    ) -> list[ReviewItem]:
        items: list[ReviewItem] = []
        project_root = self.src.resolve()
        for root_ids in root_id_groups:
            context_nodes = assembler.fetch_context_nodes_for_root_ids(root_ids)
            if not context_nodes:
                _LOGGER.warning("No context nodes found for root_ids %s; skipping", root_ids)
                continue
            if assembler.ranking_strategy.requires_taint_scores:
                taint_scores = assembler.fetch_taint_scores(root_ids)
                context_nodes = assembler.apply_taint_scores(context_nodes, taint_scores)
            context = assembler.assemble_from_nodes(project_root, context_nodes)
            root_node = next(
                (n for n in context_nodes if str(n.identifier) == root_ids[0]), context_nodes[0]
            )
            depth_zero_nodes = [node for node in context_nodes if node.depth == 0]
            items.append(
                ReviewItem(
                    root_id=root_ids[0],
                    file_path=project_root / root_node.file_path,
                    line_start=root_node.line_start,
                    line_end=root_node.line_end,
                    context_text=context.context_text,
                    static_findings=attach_findings(
                        static_findings, context.source_map, depth_zero_nodes
                    ),
                    roots=tuple(
                        ReviewRoot(
                            project_root / root.file_path, *_changed_lines(root, changed_spans)
                        )
                        for root in context.roots
                    ),
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

        root_ids = list({str(e.dst) for e in filtered_edges})
        _LOGGER.info(
            "Full scan: %d findings → %d unique root code nodes (min severity: %s)",
            len(filtered_findings),
            len(root_ids),
            min_severity,
        )

        assembler = self._build_context_assembler(strategy_factory, max_call_depth, token_budget)
        items = self._build_review_items(
            [[root_id] for root_id in root_ids], assembler, all_findings
        )
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

        Changed root nodes are packed into as few contexts as fit the budget,
        so a change's sink and the guards it relies on are reviewed together.

        Args:
            file_spans: Changed file spans parsed from a git unified diff.
            strategy_factory: Factory producing a ``ContextNodeRankingStrategy``.
            strategy_name: Human-readable name stored in the report.
            llm_review_service: Service that sends context batches to the LLM.
            max_call_depth: Maximum BFS depth when expanding the code neighborhood.
            token_budget: Approximate token limit for each assembled context.

        Returns:
            A ``ScanReport`` with one ``ScanFinding`` per reviewed context.
        """
        project_root = self.src.resolve()
        all_findings, _ = self.build_cpg()

        assembler = self._build_context_assembler(strategy_factory, max_call_depth, token_budget)
        root_id_groups = assembler.fetch_root_id_groups_for_spans(
            file_spans, int(token_budget * DIFF_ROOT_TOKEN_SHARE)
        )
        _LOGGER.info(
            "Diff scan: %d root code nodes in %d contexts from %d file spans",
            sum(len(group) for group in root_id_groups),
            len(root_id_groups),
            len(file_spans),
        )

        items = self._build_review_items(root_id_groups, assembler, all_findings, file_spans)
        findings = llm_review_service.review(items)

        return ScanReport(
            src=project_root,
            mode="diff",
            strategy=strategy_name,
            findings=findings,
            total_contexts_scanned=len(items),
        )
