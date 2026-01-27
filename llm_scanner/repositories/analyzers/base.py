from abc import ABC, abstractmethod
from models.edges.analysis import StaticAnalysisReports
from models.nodes.finding import FindingNode
from repositories.base import Neo4jRepository


class IFindingsRepository(Neo4jRepository, ABC):
    @abstractmethod
    def insert_nodes(self, findings_nodes: list[FindingNode]) -> None:
        pass

    @abstractmethod
    def insert_edges(self, dlint_relations: list[StaticAnalysisReports]) -> None:
        pass
