from functools import cached_property
from typing import Any

from clients.analyzers.pysa import PysaStaticAnalyzer
from models.nodes.finding import FindingNode, PysaFindingNode
from models.pysa_report import PysaIssue
from services.analyzer.base import BaseAnalyzerService


class PysaAnalyzerService(BaseAnalyzerService):
    @property
    def _finding_node_type(self) -> type[FindingNode]:
        return PysaFindingNode

    @cached_property
    def _static_analyzer(self) -> PysaStaticAnalyzer:
        return PysaStaticAnalyzer(src=self.project_root)

    def _issue_payload(self, issue: PysaIssue) -> dict[str, Any]:  # type: ignore
        """Normalize Pysa issue payload for finding node creation.

        Strips fields that exist on PysaIssue but not on PysaFindingNode.
        """
        payload = issue.model_dump()
        payload.pop("column_number", None)
        payload.pop("stop_line", None)
        payload.pop("stop_column", None)
        payload.pop("reason", None)
        return payload
