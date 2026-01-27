from abc import ABC, abstractmethod
from pathlib import Path

from pydantic import BaseModel

from models.base import StaticAnalyzerIssue, StaticAnalyzerReport


class IStaticAnalyzer(ABC, BaseModel):
    src: Path

    @abstractmethod
    def run(self) -> StaticAnalyzerReport[StaticAnalyzerIssue]:
        pass
