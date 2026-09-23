from models.nodes.finding import SemgrepFindingNode
from repositories.analyzers.base import IFindingsRepository
from repositories.queries import finding_node_query


class SemgrepFindingsRepository(IFindingsRepository):
    """Repository for persisting Semgrep security findings."""

    @property
    def finding_label(self) -> str:
        """Return the Neo4j label for the finding node."""

        return "SemgrepFinding"

    def insert_nodes(self, findings_nodes: list[SemgrepFindingNode]) -> None:  # type: ignore
        """Insert Semgrep finding nodes into Neo4j.

        Args:
            findings_nodes: List of Semgrep finding nodes to insert.
        """

        if not findings_nodes:
            return

        rows: list[dict[str, object]] = [
            {
                "id": str(finding.identifier),
                "file": str(finding.file),
                "line_number": finding.line_number,
                "rule_id": finding.rule_id,
                "cwe_id": finding.cwe_id,
                "severity": str(finding.severity),
            }
            for finding in findings_nodes
        ]

        query = finding_node_query("SemgrepFinding")
        self.client.run_write(query, {"rows": rows})
