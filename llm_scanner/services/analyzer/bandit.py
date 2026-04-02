from functools import cached_property
from typing import Any

from clients.analyzers.bandit import BanditStaticAnalyzer
from models.bandit_report import BanditIssue
from models.nodes.finding import BanditFindingNode, FindingNode
from services.analyzer.base import BaseAnalyzerService


class BanditAnalyzerService(BaseAnalyzerService):
    @property
    def _finding_node_type(self) -> type[FindingNode]:
        return BanditFindingNode

    @cached_property
    def _static_analyzer(self) -> BanditStaticAnalyzer:
        return BanditStaticAnalyzer(src=self.project_root)

    def _issue_payload(self, issue: BanditIssue) -> dict[str, Any]:  # type: ignore
        """Normalize Bandit issue payload for finding creation.

        Args:
            issue: Bandit issue instance.

        Returns:
            Finding payload with cwe_id.
        """

        payload = issue.model_dump()
        payload["cwe_id"] = payload.pop("cwe", None)
        payload.pop("column_number", None)
        payload.pop("line_range", None)
        return payload
