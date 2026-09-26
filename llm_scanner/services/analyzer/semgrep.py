from functools import cached_property
from typing import Any

from clients.analyzers.semgrep import DEFAULT_SEMGREP_CONFIG, SemgrepStaticAnalyzer
from models.nodes.finding import FindingNode, SemgrepFindingNode
from models.semgrep_report import SemgrepIssue
from services.analyzer.base import BaseAnalyzerService


class SemgrepAnalyzerService(BaseAnalyzerService):
    """Turn Semgrep results for ``project_root`` into finding nodes."""

    config: str = DEFAULT_SEMGREP_CONFIG

    @property
    def _finding_node_type(self) -> type[FindingNode]:
        return SemgrepFindingNode

    @cached_property
    def _static_analyzer(self) -> SemgrepStaticAnalyzer:
        return SemgrepStaticAnalyzer(src=self.project_root, config=self.config)

    def _issue_payload(self, issue: SemgrepIssue) -> dict[str, Any]:  # type: ignore
        """Normalize Semgrep issue payload for finding creation.

        Args:
            issue: Semgrep issue instance.

        Returns:
            Finding payload with rule_id and cwe_id.
        """

        payload = issue.model_dump()
        payload["rule_id"] = payload.pop("check_id")
        payload["cwe_id"] = payload.pop("cwe")
        return payload
