from functools import cached_property
from typing import Any

from clients.analyzers.dlint_scanner import DlintStaticAnalyzer
from models.dlint_report import DlintIssue
from models.nodes.finding import DlintFindingNode, FindingNode
from services.analyzer.base import BaseAnalyzerService


class DlintAnalyzerService(BaseAnalyzerService):
    @property
    def _finding_node_type(self) -> type[FindingNode]:
        return DlintFindingNode

    @cached_property
    def _static_analyzer(self) -> DlintStaticAnalyzer:
        return DlintStaticAnalyzer(src=self.target)

    def _issue_payload(self, issue: DlintIssue) -> dict[str, Any]:  # type: ignore
        """Normalize Dlint issue payload for finding creation.

        Args:
            issue: Dlint issue instance.

        Returns:
            Finding payload with issue_id.
        """

        payload = issue.model_dump()
        payload["issue_id"] = issue.id
        payload.pop("code", None)
        payload.pop("column_number", None)
        return payload
