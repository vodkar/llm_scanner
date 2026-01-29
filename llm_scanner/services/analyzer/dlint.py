from functools import cached_property

from clients.analyzers.dlint_scanner import DlintStaticAnalyzer
from models.nodes.finding import DlintFindingNode, FindingNode
from services.analyzer.base import BaseAnalyzerService


class DlintAnalyzerService(BaseAnalyzerService):
    @property
    def _finding_node_type(self) -> type[FindingNode]:
        return DlintFindingNode

    @cached_property
    def _static_analyzer(self) -> DlintStaticAnalyzer:
        return DlintStaticAnalyzer(src=self.target)
