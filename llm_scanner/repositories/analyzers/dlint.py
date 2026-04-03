from models.nodes.finding import DlintFindingNode
from repositories.analyzers.base import IFindingsRepository
from repositories.queries import finding_node_query


class DlintFindingsRepository(IFindingsRepository):
    """Repository for persisting Dlint security findings."""

    @property
    def finding_label(self) -> str:
        """Return the Neo4j label for the finding node."""

        return "DlintFinding"

    def insert_nodes(self, findings_nodes: list[DlintFindingNode]) -> None:  # type: ignore
        """Insert Dlint finding nodes into Neo4j.

        Args:
            findings_nodes: List of Dlint finding nodes to insert.
        """

        if not findings_nodes:
            return

        rows: list[dict[str, object]] = [
            {
                "id": str(finding.identifier),
                "file": str(finding.file),
                "line_number": finding.line_number,
                "issue_id": finding.issue_id,
            }
            for finding in findings_nodes
        ]

        query = finding_node_query("DlintFinding")
        self.client.run_write(query, {"rows": rows})
