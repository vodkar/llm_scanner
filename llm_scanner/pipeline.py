from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from clients.neo4j import Neo4jClient
from repositories.analyzers.bandit import BanditFindingsRepository
from repositories.analyzers.dlint import DlintFindingsRepository
from repositories.graph import GraphRepository
from services.analyzer.bandit import BanditAnalyzerService
from services.analyzer.dlint import DlintAnalyzerService
from services.context_assembler.ranking import NodeRelevanceRankingService
from services.cpg_parser.ts_parser.cpg_builder import CPGDirectoryBuilder


class GeneralPipeline(BaseModel):
    src: Path
    neo4j_client: Neo4jClient

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def run(self) -> None:
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
