from models.nodes.finding import BanditFindingNode
from repositories.analyzers.base import IFindingsRepository
from repositories.queries import finding_node_query


class BanditFindingsRepository(IFindingsRepository):
    """Repository for persisting Bandit security findings."""

    @property
    def finding_label(self) -> str:
        """Return the Neo4j label for the finding node."""

        return "BanditFinding"

    def insert_nodes(self, findings_nodes: list[BanditFindingNode]) -> None:  # type: ignore
        """Insert Bandit finding nodes into Neo4j.

        Args:
            findings_nodes: List of Bandit finding nodes to insert.
        """

        if not findings_nodes:
            return

        rows: list[dict[str, object]] = [
            {
                "id": str(finding.identifier),
                "file": str(finding.file),
                "line_number": finding.line_number,
                "cwe_id": finding.cwe_id,
                "severity": str(finding.severity),
            }
            for finding in findings_nodes
        ]

        query = finding_node_query("BanditFinding")
        self.client.run_write(query, {"rows": rows})
