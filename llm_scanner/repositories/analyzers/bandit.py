from models.edges.analysis import StaticAnalysisReports
from models.nodes.finding import BanditFindingNode
from repositories.analyzers.base import IFindingsRepository


class BanditFindingsRepository(IFindingsRepository):
    def insert_nodes(self, findings_nodes: list[BanditFindingNode]) -> None:  # type: ignore
        pass

    def insert_edges(self, dlint_relations: list[StaticAnalysisReports]) -> None:
        pass
