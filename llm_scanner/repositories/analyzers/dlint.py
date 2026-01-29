from models.edges.analysis import StaticAnalysisReports
from models.nodes.finding import DlintFindingNode
from repositories.analyzers.base import IFindingsRepository
from repositories.queries import finding_node_query, finding_relationship_query


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

    def insert_edges(self, finding_relations: list[StaticAnalysisReports]) -> None:
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
