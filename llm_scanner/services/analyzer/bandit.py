from functools import cached_property
from typing import Any, Final

from clients.analyzers.bandit import BanditStaticAnalyzer
from models.bandit_report import BanditIssue
from models.nodes.finding import BanditFindingNode, FindingNode
from services.analyzer.base import BaseAnalyzerService

# Bandit tests that flag code hygiene rather than a security weakness:
# assert statements (B101) and swallowed exceptions (B110, B112), plus
# import-only blacklist checks (B401-B410) whose risky *calls* are reported
# separately (B301-B323, B602-B607). B411-B415 stay: they have no call check.
NON_SECURITY_BANDIT_TESTS: Final[frozenset[str]] = frozenset(
    {
        "B101",
        "B110",
        "B112",
        "B401",
        "B402",
        "B403",
        "B404",
        "B405",
        "B406",
        "B407",
        "B408",
        "B409",
        "B410",
    }
)


class BanditAnalyzerService(BaseAnalyzerService):
    @property
    def _finding_node_type(self) -> type[FindingNode]:
        return BanditFindingNode

    @cached_property
    def _static_analyzer(self) -> BanditStaticAnalyzer:
        return BanditStaticAnalyzer(src=self.project_root)

    def _is_security_relevant(self, issue: BanditIssue) -> bool:  # type: ignore
        """Drop Bandit tests listed in ``NON_SECURITY_BANDIT_TESTS``."""

        return issue.test_id not in NON_SECURITY_BANDIT_TESTS

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
