from models.nodes.finding import BugbearFindingNode
from repositories.analyzers.base import IFindingsRepository
from repositories.queries import finding_node_query


class BugbearFindingsRepository(IFindingsRepository):
    """Repository for persisting flake8-bugbear findings."""

    @property
    def finding_label(self) -> str:
        """Return the Neo4j label for the finding node."""

        return "BugbearFinding"

    def insert_nodes(self, findings_nodes: list[BugbearFindingNode]) -> None:  # type: ignore
        """Insert bugbear finding nodes into Neo4j.

        Args:
            findings_nodes: List of bugbear finding nodes to insert.
        """

        if not findings_nodes:
            return

        rows: list[dict[str, object]] = [
            {
                "id": str(finding.identifier),
                "file": str(finding.file),
                "line_number": finding.line_number,
                "rule_id": finding.rule_id,
                "severity": finding.severity,
            }
            for finding in findings_nodes
        ]

        self.client.run_write(finding_node_query("BugbearFinding"), {"rows": rows})
