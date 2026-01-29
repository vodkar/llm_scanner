from models.edges.analysis import StaticAnalysisReports
from models.nodes.finding import BanditFindingNode
from repositories.analyzers.base import IFindingsRepository
from repositories.queries import finding_node_query, finding_relationship_query


class BanditFindingsRepository(IFindingsRepository):
    """Repository for persisting Bandit security findings."""

    def insert_nodes(self, findings_nodes: list[BanditFindingNode]) -> None:  # type: ignore
        """Insert Bandit finding nodes into Neo4j.

        Args:
            findings_nodes: List of Bandit finding nodes to insert.
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
                    "cwe_id": payload["cwe_id"],
                    "severity": str(payload["severity"]),
                }
            )

        query = finding_node_query("BanditFinding")
        self.client.run_write(query, {"rows": rows})

    def insert_edges(self, finding_relations: list[StaticAnalysisReports]) -> None:
        """Insert Bandit finding relationships into Neo4j.

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
