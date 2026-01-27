from pydantic import BaseModel

from models.edges.analysis import StaticAnalysisReports
from models.nodes.finding import BanditFindingNode
from repositories.base import Neo4jRepository


class BanditFindingsRepository(Neo4jRepository):
    def insert_nodes(self, bandit_findings_nodes: list[BanditFindingNode]) -> None:
        pass

    def insert_edges(self, bandit_relations: list[StaticAnalysisReports]) -> None:
        pass
