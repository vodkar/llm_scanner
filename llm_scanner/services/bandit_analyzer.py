from collections import defaultdict
from pathlib import Path

from pydantic import BaseModel
from models.edges.analysis import StaticAnalysisReports
from models.nodes.finding import BanditFindingNode
from repositories.bandit import BanditFindingsRepository
from repositories.graph import GraphRepository
from clients.analyzers.bandit_scanner import BanditScanner


class BanditAnalyzerService(BaseModel):

    graph_repository: GraphRepository
    bandit_findings_repository: BanditFindingsRepository
    bandit_scanner: BanditScanner

    def enrich_graph_with_findings(self) -> None:
        report = self.bandit_scanner.run_scanner()

        issues_in_files_lines: dict[Path, list[int]] = defaultdict(list)
        for issue in report.issues:
            issues_in_files_lines[issue.file].append(issue.line_number)

        nodes = self.graph_repository.get_nodes_by_file_and_line_numbers(
            issues_in_files_lines
        )

        findings: list[BanditFindingNode] = []
        edges: list[StaticAnalysisReports] = []
        for issue in report.issues:
            finding = BanditFindingNode(
                file=issue.file,
                line_number=issue.line_number,
                cwe_id=issue.cwe,
                severity=issue.severity,
            )
            findings.append(finding)
            edges.append(
                StaticAnalysisReports(
                    src=str(finding.identifier),
                    dst=nodes[finding.file][finding.line_number].identifier,
                )
            )

        self.bandit_findings_repository.insert_nodes(findings)
        self.bandit_findings_repository.insert_edges(edges)
