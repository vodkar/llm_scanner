from functools import cached_property
from typing import Any

from clients.analyzers.bugbear_scanner import BugbearStaticAnalyzer
from models.bugbear_report import BugbearIssue
from models.nodes.finding import BugbearFindingNode, FindingNode
from services.analyzer.base import BaseAnalyzerService


class BugbearAnalyzerService(BaseAnalyzerService):
    """Report security-relevant Python pitfalls (shared state, silenced errors) via bugbear."""

    @property
    def _finding_node_type(self) -> type[FindingNode]:
        return BugbearFindingNode

    @cached_property
    def _static_analyzer(self) -> BugbearStaticAnalyzer:
        return BugbearStaticAnalyzer(src=self.project_root)

    def _issue_payload(self, issue: BugbearIssue) -> dict[str, Any]:  # type: ignore
        """Normalize a bugbear issue payload for finding creation.

        Args:
            issue: Bugbear issue instance.

        Returns:
            Finding payload with ``rule_id``.
        """

        payload = issue.model_dump()
        payload["rule_id"] = payload.pop("code")
        return payload
