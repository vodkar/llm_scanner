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
            Finding payload with cwe_id, rule_id and line_end.
        """

        payload = issue.model_dump()
        payload["cwe_id"] = payload.pop("cwe", None)
        payload["rule_id"] = payload.pop("test_id", "")
        payload["column_number"] = max(payload["column_number"], 0)
        line_range: list[int] = payload.pop("line_range", [])
        payload["line_end"] = max(line_range) if line_range else None
        return payload
