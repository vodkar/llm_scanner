from abc import abstractmethod
from collections import defaultdict
from functools import cached_property
from pathlib import Path

from pydantic import BaseModel
from clients.analyzers.base import IStaticAnalyzer
from models.edges.analysis import StaticAnalysisReports
from models.nodes.finding import FindingNode
from repositories.analyzers.base import IFindingsRepository
from repositories.graph import GraphRepository


class BaseAnalyzerService(BaseModel):

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

    def enrich_graph_with_findings(self) -> None:
        report = self._static_analyzer.run()

        issues_in_files_lines: dict[Path, list[int]] = defaultdict(list)
        for issue in report.issues:
            issues_in_files_lines[issue.file].append(issue.line_number)

        nodes = self.graph_repository.get_nodes_by_file_and_line_numbers(
            issues_in_files_lines
        )

        findings: list[FindingNode] = []
        edges: list[StaticAnalysisReports] = []
        for issue in report.issues:
            finding = self._finding_node_type(**issue.model_dump())
            findings.append(finding)
            edges.append(
                StaticAnalysisReports(
                    src=str(finding.identifier),
                    dst=nodes[finding.file][finding.line_number].identifier,
                )
            )

        self.findings_repository.insert_nodes(findings)
        self.findings_repository.insert_edges(edges)
