"""Attach evidence roles, CPG confidence, and lexical-fallback flags to candidates.

The annotator inlines what TASK.md described as separate "CPG feature provider"
and "vulnerability classifier" steps: CPG features come straight off the
``CodeContextNode`` (``edge_depths`` / ``taint_score`` / ``finding_evidence_score``),
and the CWE→roles registry is a small module-level constant rather than a
service of its own.

Role assignment is deterministic and rule-ordered (see ``annotate``).
"""

from pathlib import Path
from typing import Final

from pydantic import BaseModel, ConfigDict

from models.context_ranking import EvidenceRole, RankingCandidate
from services.ranking.ranking import (
    GENERATED_FILE_SUFFIXES,
    GENERATED_HEADER_MARKERS,
    GENERATED_PATH_MARKERS,
    GUARD_HINTS,
    SINK_HINTS,
    SOURCE_HINTS,
)
from services.snippet_reader import SnippetReaderService

# CPG edge types we treat as evidence channels. Order is stable so
# cpg_confidence is reproducible across runs.
KNOWN_CPG_EDGE_TYPES: Final[tuple[str, ...]] = (
    "FLOWS_TO",
    "SANITIZED_BY",
    "CALLS",
    "CALLED_BY",
    "DEFINED_BY",
    "USED_BY",
    "CONTAINS",
)

# CWE → expected role hints. Used when a finding's CWE is propagated into the
# annotator (Spec 2 may carry CWE metadata on the candidate; in Spec 1 we only
# observe the scalar finding_evidence_score, so this constant is consulted by
# higher layers and reserved for future expansion). It mirrors the high-risk
# CWE set in ranking.py:73-96.
CWE_EXPECTED_ROLES: Final[dict[int, frozenset[EvidenceRole]]] = {
    22: frozenset({EvidenceRole.SINK}),
    77: frozenset({EvidenceRole.SINK}),
    78: frozenset({EvidenceRole.SINK}),
    79: frozenset({EvidenceRole.SINK}),
    89: frozenset({EvidenceRole.SINK}),
    94: frozenset({EvidenceRole.SINK}),
    95: frozenset({EvidenceRole.SINK}),
    98: frozenset({EvidenceRole.SINK}),
    502: frozenset({EvidenceRole.SINK}),
    611: frozenset({EvidenceRole.SINK}),
    918: frozenset({EvidenceRole.SINK}),
}

_FINDING_EVIDENCE_SINK_THRESHOLD: Final[float] = 0.5


class SemanticAnnotator(BaseModel):
    """Assign evidence roles to ranking candidates."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    project_root: Path
    snippet_reader: SnippetReaderService

    def annotate(self, candidates: list[RankingCandidate]) -> list[RankingCandidate]:
        """Return candidates annotated with roles, cpg_confidence, fallback flag."""

        return [self._annotate_one(c) for c in candidates]

    def _annotate_one(self, candidate: RankingCandidate) -> RankingCandidate:
        node = candidate.source_node
        snippet = self.snippet_reader.read_snippet(
            node.file_path,
            candidate.clipped_line_start,
            candidate.clipped_line_end,
        )

        if self._is_generated_file(node.file_path, snippet):
            return candidate.model_copy(
                update={
                    "roles": frozenset({EvidenceRole.BOILERPLATE}),
                    "cpg_confidence": self._cpg_confidence(node.edge_depths),
                    "lexical_fallback_only": False,
                }
            )

        roles: set[EvidenceRole] = set()
        cpg_signal = False
        analyzer_signal = False

        if node.depth == 0:
            roles.add(EvidenceRole.ROOT)

        edge_depths = node.edge_depths or {}
        if "SANITIZED_BY" in edge_depths:
            roles.add(EvidenceRole.SANITIZER)
            cpg_signal = True
        if "FLOWS_TO" in edge_depths:
            roles.add(EvidenceRole.PROPAGATION)
            cpg_signal = True
        if "CALLS" in edge_depths:
            roles.add(EvidenceRole.CALLER)
            cpg_signal = True
        if "CALLED_BY" in edge_depths:
            roles.add(EvidenceRole.CALLEE)
            cpg_signal = True
        if "DEFINED_BY" in edge_depths:
            roles.add(EvidenceRole.DEFINITION)
            cpg_signal = True

        if node.taint_score > 0.0:
            roles.add(EvidenceRole.PROPAGATION)
            cpg_signal = True

        normalized_text = snippet.lower()
        lexical_signal = False
        if any(hint in normalized_text for hint in SINK_HINTS):
            roles.add(EvidenceRole.SINK)
            lexical_signal = True
        if any(hint in normalized_text for hint in SOURCE_HINTS):
            roles.add(EvidenceRole.SOURCE)
            lexical_signal = True
        if any(hint in normalized_text for hint in GUARD_HINTS):
            roles.add(EvidenceRole.GUARD)
            lexical_signal = True

        if node.finding_evidence_score >= _FINDING_EVIDENCE_SINK_THRESHOLD:
            roles.add(EvidenceRole.SINK)
            analyzer_signal = True

        if not roles:
            roles.add(EvidenceRole.ENCLOSING_CONTEXT)

        lexical_fallback_only = (lexical_signal or not roles - {EvidenceRole.ROOT}) and not (
            cpg_signal or analyzer_signal
        )
        if EvidenceRole.ENCLOSING_CONTEXT in roles and not (cpg_signal or analyzer_signal):
            lexical_fallback_only = True

        return candidate.model_copy(
            update={
                "roles": frozenset(roles),
                "cpg_confidence": self._cpg_confidence(node.edge_depths),
                "lexical_fallback_only": lexical_fallback_only,
            }
        )

    @staticmethod
    def _cpg_confidence(edge_depths: dict[str, int] | None) -> float:
        if not edge_depths:
            return 0.0
        present = sum(1 for et in KNOWN_CPG_EDGE_TYPES if et in edge_depths)
        return present / len(KNOWN_CPG_EDGE_TYPES)

    @staticmethod
    def _is_generated_file(file_path: Path, snippet: str) -> bool:
        normalized_path = file_path.as_posix().lower()
        if any(normalized_path.endswith(suffix) for suffix in GENERATED_FILE_SUFFIXES):
            return True
        if any(marker in normalized_path.split("/") for marker in GENERATED_PATH_MARKERS):
            return True
        header = "\n".join(snippet.splitlines()[:3]).lower()
        return any(marker in header for marker in GENERATED_HEADER_MARKERS)
