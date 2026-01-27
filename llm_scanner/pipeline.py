from pathlib import Path

from clients.neo4j import Neo4jClient
from repositories.graph import GraphRepository
from models.base import NodeID
from models.edges import RelationshipBase
from models.nodes import Node
from pydantic import BaseModel
from clients.analyzers.bandit_scanner import BanditScanner
from services.cpg_parser.ts_parser.cpg_builder import CPGDirectoryBuilder
from services.deadcode import DeadCodeService
from services.dlint_scanner import DlintScanner
from services.formatting import FormattingService
from services.remove_comments import RemoveCommentsService


class GeneralPipeline(BaseModel):
    src: Path

    def run(self) -> None:
        deadcode_remover = DeadCodeService(src=self.src)
        formatter = FormattingService(src=self.src)
        comments_remover = RemoveCommentsService(src=self.src)
        bandit_scanner = BanditScanner(src=self.src)
        dlint_scanner = DlintScanner(src=self.src)
        client = Neo4jClient()
        graph_loader = GraphRepository(client=client)

        comments_remover.remove()
        deadcode_remover.remove()
        formatter.format()

        nodes: dict[NodeID, Node]
        edges: list[RelationshipBase]
        nodes, edges = CPGDirectoryBuilder(root=self.src.resolve()).build()
        bandit_report = bandit_scanner.run_scanner()

        graph_loader.load(nodes, edges)
