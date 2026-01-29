from models.nodes.finding import DlintFindingNode
from repositories.analyzers.base import IFindingsRepository
from repositories.queries import finding_node_query


class DlintFindingsRepository(IFindingsRepository):
    """Repository for persisting Dlint security findings."""

    def insert_nodes(self, findings_nodes: list[DlintFindingNode]) -> None:  # type: ignore
        """Insert Dlint finding nodes into Neo4j.

        Args:
            findings_nodes: List of Dlint finding nodes to insert.
        """

        if not findings_nodes:
            return

        rows: list[dict[str, object]] = []
        for finding in findings_nodes:
            payload = finding.model_dump(mode="json")
            rows.append(
                {
                    "id": str(finding.identifier),
                    "file": str(payload["file"]),
                    "line_number": payload["line_number"],
                    "issue_id": payload["issue_id"],
                }
            )

        query = finding_node_query("DlintFinding")
        self.client.run_write(query, {"rows": rows})
