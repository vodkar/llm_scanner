from pathlib import Path

from clients.neo4j import Neo4jClient
from loaders.graph_loader import GraphLoader
from models.base import NodeID
from models.edges import RelationshipBase
from models.nodes import Node
from pydantic import BaseModel
from services.bandit_scanner import BanditScanner
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
        graph_loader = GraphLoader(client=client)

        comments_remover.remove()
        deadcode_remover.remove()
        formatter.format()

        nodes: dict[NodeID, Node]
        edges: list[RelationshipBase]
        nodes, edges = CPGDirectoryBuilder(root=self.src.resolve()).build()
        bandit_report = bandit_scanner.run_scanner()
        dlint_report = dlint_scanner.run_scanner()

        graph_loader.load(nodes, edges)
        graph_loader.load_bandit_report(bandit_report)
        graph_loader.load_dlint_report(dlint_report)
