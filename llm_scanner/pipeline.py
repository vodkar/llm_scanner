from pathlib import Path

from clients.neo4j import Neo4jClient, build_client
from repositories.analyzers.bandit import BanditFindingsRepository
from repositories.analyzers.dlint import DlintFindingsRepository
from repositories.graph import GraphRepository
from models.base import NodeID
from models.edges import RelationshipBase
from models.nodes import Node
from pydantic import BaseModel
from clients.analyzers.bandit import BanditStaticAnalyzer
from services.analyzer.bandit import BanditAnalyzerService
from services.analyzer.dlint import DlintAnalyzerService
from services.cpg_parser.ts_parser.cpg_builder import CPGDirectoryBuilder
from clients.analyzers.dlint_scanner import DlintStaticAnalyzer
from services.remove_comments import RemoveCommentsService


class GeneralPipeline(BaseModel):
    src: Path

    def run(self) -> None:
        with build_client("", "", "") as neo4j_client:
            graph_repository = GraphRepository(neo4j_client)

            nodes, edges = CPGDirectoryBuilder(root=self.src.resolve()).build()
            graph_repository.load(nodes, edges)

            dlint_analyzer_service = DlintAnalyzerService(
                target=self.src,
                graph_repository=graph_repository,
                findings_repository=DlintFindingsRepository(client=neo4j_client),
            )
            dlint_analyzer_service.enrich_graph_with_findings()

            bandit_analyzer_service = BanditAnalyzerService(
                target=self.src,
                graph_repository=graph_repository,
                findings_repository=BanditFindingsRepository(client=neo4j_client),
            )
            bandit_analyzer_service.enrich_graph_with_findings
