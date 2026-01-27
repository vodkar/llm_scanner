from models.edges.analysis import StaticAnalysisReports
from models.nodes.finding import DlintFindingNode
from repositories.analyzers.base import IFindingsRepository


class DlintFindingsRepository(IFindingsRepository):
    def insert_nodes(self, findings_nodes: list[DlintFindingNode]) -> None:  # type: ignore
        pass

    def insert_edges(self, dlint_relations: list[StaticAnalysisReports]) -> None:
        pass
