from abc import ABC, abstractmethod

from models.edges.analysis import StaticAnalysisReports
from models.nodes.finding import FindingNode
from repositories.base import Neo4jRepository
from repositories.queries import finding_relationship_query


class IFindingsRepository(Neo4jRepository, ABC):
    """Abstract base repository for security findings."""

    @abstractmethod
    def insert_nodes(self, findings_nodes: list[FindingNode]) -> None:
        """Insert finding nodes into the database.

        Args:
            findings_nodes: List of finding nodes to persist.
        """

    def insert_edges(self, finding_relations: list[StaticAnalysisReports]) -> None:
        """Insert finding relationships into the database.

        Args:
            finding_relations: List of relationships connecting findings to code.
        """
        """Insert Dlint finding relationships into Neo4j.

        Args:
            finding_relations: List of relationships connecting findings to code.
        """

        if not finding_relations:
            return

        rows: list[dict[str, str]] = []
        for rel in finding_relations:
            rows.append(
                {
                    "src": str(rel.src),
                    "dst": str(rel.dst),
                }
            )

        query = finding_relationship_query("REPORTS")
        self.client.run_write(query, {"rows": rows})
