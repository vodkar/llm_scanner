from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from models.edges.analysis import StaticAnalysisReports
from models.nodes.finding import FindingNode
from repositories.base import Neo4jRepository
from repositories.queries import finding_relationship_query, findings_by_label_query


class IFindingsRepository(Neo4jRepository, ABC):
    """Abstract base repository for security findings."""

    @property
    @abstractmethod
    def finding_label(self) -> str:
        """Return the Neo4j label for the finding node."""

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

    def _iter_findings_for_project(self, project_root: Path) -> list[dict[str, Any]]:
        """Return all findings rows that belong to a project directory.

        Args:
            project_root: Root directory of the project.

        Returns:
            Raw finding rows whose file paths fall under the provided root.

        Raises:
            ValueError: When project_root is not provided.
        """

        if not project_root:
            raise ValueError("project_root must be provided")

        root_path = Path(project_root.as_posix())
        root_is_absolute: bool = root_path.is_absolute()
        normalized_root = root_path.as_posix().replace("\\", "/")
        if not root_is_absolute and normalized_root.startswith("./"):
            normalized_root = normalized_root[2:]
        if normalized_root in {"", "."}:
            root_parts: tuple[str, ...] = ()
        else:
            root_parts = tuple(part for part in normalized_root.split("/") if part and part != ".")

        query = findings_by_label_query(self.finding_label)
        rows: list[dict[str, Any]] = self.client.run_read(query)
        filtered_rows: list[dict[str, Any]] = []
        for row in rows:
            raw_file: str = str(row["file"]).replace("\\", "/")
            file_path = Path(raw_file)

            if file_path.is_absolute():
                file_parts: tuple[str, ...] = tuple(
                    part for part in file_path.as_posix().split("/") if part
                )
                if file_parts[: len(root_parts)] == root_parts:
                    filtered_rows.append(row)
                continue

            normalized_file = raw_file
            if normalized_file.startswith("./"):
                normalized_file = normalized_file[2:]

            if normalized_file in {"..", "."} or normalized_file.startswith("../"):
                continue

            if root_is_absolute:
                filtered_rows.append(row)
                continue

            file_parts = tuple(part for part in normalized_file.split("/") if part)
            if file_parts[: len(root_parts)] == root_parts:
                filtered_rows.append(row)

        return filtered_rows
