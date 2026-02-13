import os
from abc import abstractmethod
from collections import defaultdict
from functools import cached_property
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from clients.analyzers.base import IStaticAnalyzer
from models.edges.analysis import StaticAnalysisReports
from models.nodes.finding import FindingNode
from repositories.analyzers.base import IFindingsRepository
from repositories.graph import GraphRepository


class BaseAnalyzerService(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    target: Path
    graph_repository: GraphRepository
    findings_repository: IFindingsRepository

    @property
    @abstractmethod
    def _finding_node_type(self) -> type[FindingNode]:
        pass

    @cached_property
    @abstractmethod
    def _static_analyzer(self) -> IStaticAnalyzer:
        pass

    def _normalize_issue_path(self, file_path: Path) -> Path:
        """Normalize issue paths relative to the scan target.

        Args:
            file_path: Path reported by the analyzer.

        Returns:
            Relative path suitable for repository and graph matching.
        """

        target_root: Path = self.target.resolve()
        absolute_path: Path = (
            file_path if file_path.is_absolute() else (target_root / file_path)
        ).resolve()
        try:
            relative_path: Path = absolute_path.relative_to(target_root)
            return Path(relative_path.as_posix())
        except ValueError:
            rel_str: str = os.path.relpath(absolute_path.as_posix(), target_root.as_posix())
            return Path(rel_str)

    def enrich_graph_with_findings(self) -> None:
        report = self._static_analyzer.run()

        issues_in_files_lines: dict[Path, list[int]] = defaultdict(list)
        for issue in report.issues:
            normalized_path: Path = self._normalize_issue_path(issue.file)
            issues_in_files_lines[normalized_path].append(issue.line_number)

        nodes = self.graph_repository.get_nodes_by_file_and_line_numbers(issues_in_files_lines)

        findings: list[FindingNode] = []
        edges: list[StaticAnalysisReports] = []
        for issue in report.issues:
            normalized_path = self._normalize_issue_path(issue.file)
            payload = issue.model_dump()
            payload["file"] = normalized_path
            finding = self._finding_node_type(**payload)
            findings.append(finding)
            edges.append(
                StaticAnalysisReports(
                    src=str(finding.identifier),
                    dst=nodes[finding.file][finding.line_number].identifier,
                )
            )

        self.findings_repository.insert_nodes(findings)
        self.findings_repository.insert_edges(edges)
