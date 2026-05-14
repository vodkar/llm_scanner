from enum import Enum


class RankingStrategy(str, Enum):
    CPG_STRUCTURAL = "cpg_structural"
    CURRENT = "current"
    EVIDENCE_BUDGETED = "evidence_budgeted"
