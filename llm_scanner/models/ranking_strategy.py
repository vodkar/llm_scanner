from enum import Enum


class RankingStrategy(str, Enum):
    cpg_structural = "cpg_structural"
    current = "current"
    evidence_budgeted = "evidence_budgeted"
