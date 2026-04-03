from models.nodes.finding import PysaFindingNode
from repositories.analyzers.base import IFindingsRepository
from repositories.queries import finding_node_query


class PysaFindingsRepository(IFindingsRepository):
    """Repository for persisting Pysa taint flow findings."""

    @property
    def finding_label(self) -> str:
        return "PysaFinding"

    def insert_nodes(self, findings_nodes: list[PysaFindingNode]) -> None:  # type: ignore
        """Insert Pysa finding nodes into Neo4j.

        Args:
            findings_nodes: List of Pysa finding nodes to insert.
        """

        if not findings_nodes:
            return

        rows: list[dict[str, object]] = [
            {
                "id": str(finding.identifier),
                "file": str(finding.file),
                "line_number": finding.line_number,
                "flow_code": finding.flow_code,
                "flow_name": finding.flow_name,
                "sink_type": str(finding.sink_type),
                "source_type": str(finding.source_type) if finding.source_type else None,
            }
            for finding in findings_nodes
        ]

        query = finding_node_query("PysaFinding")
        self.client.run_write(query, {"rows": rows})
