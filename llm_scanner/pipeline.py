from pathlib import Path

from clients.neo4j import Neo4jClient
from entrypoints.base import parse_project_to_cpg
from loaders.graph_loader import GraphLoader
from pydantic import BaseModel
from services.deadcode import DeadCodeService
from services.formatting import FormattingService
from services.remove_comments import RemoveCommentsService


class GeneralPipeline(BaseModel):
    src: Path

    def run(self):
        deadcode_remover = DeadCodeService(src=self.src)
        formatter = FormattingService(src=self.src)
        comments_remover = RemoveCommentsService(src=self.src)
        client = Neo4jClient()
        graph_loader = GraphLoader(client=client)

        comments_remover.remove()
        deadcode_remover.remove()
        formatter.format()

        nodes, edges = parse_project_to_cpg(self.src)

        graph_loader.load(nodes, edges)
