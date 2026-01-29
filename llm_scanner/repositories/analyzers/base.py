from abc import ABC, abstractmethod

from models.edges.analysis import StaticAnalysisReports
from models.nodes.finding import FindingNode
from repositories.base import Neo4jRepository


class IFindingsRepository(Neo4jRepository, ABC):
    """Abstract base repository for security findings."""

    @abstractmethod
    def insert_nodes(self, findings_nodes: list[FindingNode]) -> None:
        """Insert finding nodes into the database.

        Args:
            findings_nodes: List of finding nodes to persist.
        """

    @abstractmethod
    def insert_edges(self, finding_relations: list[StaticAnalysisReports]) -> None:
        """Insert finding relationships into the database.

        Args:
            finding_relations: List of relationships connecting findings to code.
        """
