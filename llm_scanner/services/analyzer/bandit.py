from functools import cached_property
from clients.analyzers.bandit import BanditStaticAnalyzer
from models.nodes.finding import BanditFindingNode, FindingNode
from services.analyzer.base import BaseAnalyzerService


class BanditAnalyzerService(BaseAnalyzerService):
    @property
    def _finding_node_type(self) -> type[FindingNode]:
        return BanditFindingNode

    @cached_property
    def _static_analyzer(self) -> BanditStaticAnalyzer:
        return BanditStaticAnalyzer(src=self.target)
