"""LLM-based code review service for the CI scanner pipeline."""

import asyncio
import hashlib
import json
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Final, NamedTuple

from pydantic import BaseModel, ConfigDict, Field

from clients.openai_compatible import ChatMessage, OpenAICompatibleClient
from models.scan import ScanFinding, ScanSeverity
from models.static_finding import StaticFinding

_LOGGER: Final[logging.Logger] = logging.getLogger(__name__)

# Verbatim ``strict_exploitable_security_v2_root_findings`` from the llm4codesec-framework
# prompt set; the scanner-specific layout and answer format follow it.
_STRICT_EXPLOITABLE_V2_SYSTEM_PROMPT: Final[str] = (
    "You are a code security analyst. Determine whether the code under analysis contains "
    "a REAL, EXPLOITABLE security vulnerability — a flaw that an attacker can actually "
    "trigger.\n\n"
    "Methodology:\n"
    "1. Identify the trust boundary and every untrusted input source (function "
    "parameters, user input, network data, files, environment, IPC, deserialized data, "
    "responses from remote servers or peers).\n"
    "2. Identify security-sensitive sinks (command/SQL/code execution, deserialization, "
    "template rendering and HTML output, memory operations, file/path access, outbound "
    "requests, redirects, headers and cookies, logs, authentication, authorization, "
    "cryptography).\n"
    "3. Trace whether attacker-controlled data can reach a sink without adequate "
    "validation, sanitization, encoding, or bounds checking (source-to-sink data flow).\n"
    "4. Check for missing controls. If the code is an entry point or an enforcement "
    "point (request or protocol handler, authentication or verification routine, "
    "permission check, validator, sanitizer, sandbox, redirect handler, parser of "
    "untrusted data), list the controls it must enforce — authentication; authorization "
    "scoped to the specific object, user and tenant; CSRF protection or HTTP method "
    "checks on state changes; account status; limits on the size, count, depth or time "
    "of untrusted input; secure settings such as TLS verification, cookie attributes and "
    "file permissions — and cite the line that enforces each. A required control that is "
    "absent from the shown code is a flaw; do not assume a caller or framework provides "
    "it unless the shown code demonstrates it.\n"
    "5. Test the guards that are present. Before crediting a sanitizer, validator, "
    "escape function or check, try a concrete bypass against its exact semantics: case "
    "variants, alternative encodings or Unicode normalization, '..' and '//' path forms, "
    "parts of the input the check skips, parameters or branches it does not cover, None "
    "or empty values, error handlers that fail open, non-constant-time comparison of "
    "secrets. A guard that a concrete input bypasses does not protect.\n"
    "6. Confirm exploitability: the path must be reachable, the data "
    "attacker-controllable, and the impact concrete.\n\n"
    "Rules:\n"
    "- Report a vulnerability ONLY if you can name the flawed line (or the missing "
    "control) and describe a concrete attack: who the attacker is, what input they send, "
    "and the resulting impact.\n"
    "- A guard performed inside a called library or framework API counts when its "
    "documented behavior covers the attack (e.g. path-confining file serving, "
    "parameterized queries, autoescaping templates). An attack that only works if the "
    'library "fails to sanitize" is not concrete: name the bypass against the API\'s '
    "actual behavior, or classify the code as not vulnerable.\n"
    "- Attackers include remote users, lower-privileged or other-tenant users, malicious "
    "remote servers and peers, and other local users on a shared machine.\n"
    "- Concrete impacts include code execution, injection, XSS, authentication or "
    "access-control bypass, CSRF, disclosure of secrets or other users' data, credential "
    "leakage, SSRF, open redirect, request smuggling, and denial of service triggered by "
    "untrusted input (crash, hang, unbounded memory or CPU).\n"
    "- Theoretical, stylistic, or best-practice concerns without such an attack are NOT "
    'vulnerabilities. Calling code a "standard pattern" or "intended functionality" is '
    "not by itself a reason to consider it safe.\n"
    "- If the flaw is not reachable or not attacker-controllable, or the evidence is "
    "insufficient, classify the code as not vulnerable. False alarms are costly.\n\n"
    "Numeric inputs that change persistent state (quantities, amounts, prices, balances, "
    "counts, indexes, durations) must be checked for sign and range, not only type. If an "
    "attacker can send a negative, zero or oversized value that inverts or bypasses the "
    "intended effect (a negative withdrawal that adds stock, a negative price that credits "
    "the buyer, an out-of-bounds index), report it and cite the line that should enforce "
    "the bound; typical CWEs are CWE-20, CWE-1284 and CWE-840."
)

_SCANNER_OUTPUT_INSTRUCTIONS: Final[str] = (
    "\n\nInput layout: each '# ===== ROOT i/N' section is code under analysis, and the "
    "'# ----- CONTEXT for ROOT i' section after it is reference-only code related to that "
    "root (callers, callees, definitions). Judge only the ROOT code; use its CONTEXT to "
    "trace inputs and called behavior.\n\n"
    "After you have finished reasoning, output a JSON object on its own final line "
    'with exactly these keys: "vulnerable" (bool), "severity" '
    '("LOW", "MEDIUM", "HIGH", or "CRITICAL", or null if not vulnerable), '
    '"description" (string describing the issue, or null if not vulnerable), '
    '"cwe_id" (integer CWE number, or null), '
    '"root" (integer i of the ROOT i/N section containing the flaw, or null if not '
    "vulnerable)."
)

_REVIEW_SYSTEM_PROMPT: Final[str] = (
    _STRICT_EXPLOITABLE_V2_SYSTEM_PROMPT + _SCANNER_OUTPUT_INSTRUCTIONS
)

_REVIEW_USER_TEMPLATE: Final[str] = (
    "Analyze this code for a real, exploitable security vulnerability:\n\n"
    "{code}{root_static_findings}"
)

_ROOT_FINDINGS_HEADER: Final[str] = (
    "Static analyzer findings in the function under analysis "
    "(automated tools; may be false positives):"
)
_NO_ROOT_FINDINGS_TEXT: Final[str] = (
    "Static analyzer findings in the function under analysis: none reported."
)
_ROOT_FINDINGS_SEPARATOR: Final[str] = "\n\n"
_ROOT_MARKER_PREFIX: Final[str] = "# ===== ROOT "

_JSON_DECODER: Final[json.JSONDecoder] = json.JSONDecoder()
_SAMPLING_SEED: Final[int] = 42
_SEED_MODULUS: Final[int] = 2**31 - 1


def _context_seed(context_text: str) -> int:
    """Derive a stable per-context sampling seed, so reruns draw the same samples."""
    digest = hashlib.sha256(f"{_SAMPLING_SEED}|{context_text}".encode()).digest()
    return int.from_bytes(digest[:8], "big") % _SEED_MODULUS


def _verdict_candidates(response: str) -> Iterator[dict[str, Any]]:
    """Yield JSON objects with a ``vulnerable`` key, the last one in ``response`` first.

    Decoding starts at each ``{`` from the end, so code fences, trailing prose and
    braces quoted inside string values (e.g. ``f"ORDER BY {field}"``) are tolerated.
    """
    position = response.rfind("{")
    while position != -1:
        try:
            parsed, _ = _JSON_DECODER.raw_decode(response, position)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict) and "vulnerable" in parsed:
            yield parsed
        position = response.rfind("{", 0, position)


def _nullable(schema: dict[str, Any]) -> dict[str, Any]:
    return {"anyOf": [schema, {"type": "null"}]}


def _review_response_format() -> dict[str, Any]:
    """Return the OpenAI ``response_format`` constraining replies to the review verdict."""
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "security_review_verdict",
            "strict": True,
            "schema": {
                "type": "object",
                "properties": {
                    "vulnerable": {"type": "boolean"},
                    "severity": _nullable(
                        {"type": "string", "enum": [severity.value for severity in ScanSeverity]}
                    ),
                    "description": _nullable({"type": "string"}),
                    "cwe_id": _nullable({"type": "integer", "minimum": 1, "maximum": 99999}),
                    "root": _nullable({"type": "integer", "minimum": 1}),
                },
                "required": ["vulnerable", "severity", "description", "cwe_id", "root"],
                "additionalProperties": False,
            },
        },
    }


class _Verdict(NamedTuple):
    vulnerable: bool
    severity: ScanSeverity | None
    description: str | None
    cwe_id: int | None
    root: int | None


class ReviewRoot(NamedTuple):
    """Location of one ``ROOT i/N`` section of a review context."""

    file_path: Path
    line_start: int
    line_end: int


class ReviewItem(NamedTuple):
    """Inputs for one LLM review request."""

    root_id: str
    file_path: Path
    line_start: int
    line_end: int
    context_text: str
    static_findings: list[StaticFinding]
    """Analyzer findings resolved into ``context_text``; ``is_root`` ones go into the prompt."""
    roots: tuple[ReviewRoot, ...] = ()
    """Locations of the context's ROOT sections, in rendered order."""


class LLMCodeReviewService(BaseModel):
    """Review assembled code contexts with an LLM and return structured findings.

    Each item is sent as one chat completion request drawing
    ``self_consistency_samples`` completions via
    ``OpenAICompatibleClient.chat_batch_samples()``. Each completion is parsed
    for a terminal JSON verdict (unparseable ones count as not vulnerable and
    are logged), and the finding takes the majority verdict.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    client: OpenAICompatibleClient
    concurrency: int = 8
    max_response_tokens: int = 2048
    structured_output: bool = False
    """Constrain replies to the verdict JSON schema via ``response_format``.

    Needed for models that ignore the answer-format instruction (e.g. agent
    fine-tunes that reply with tool calls); reasoning still precedes the JSON.
    """
    self_consistency_samples: int = Field(default=1, ge=1)
    """Completions drawn per context; the verdict is their majority vote."""

    def review(self, items: list[ReviewItem]) -> list[ScanFinding]:
        """Send all items to the LLM and return a structured ScanFinding for each.

        Each item is one request drawing ``self_consistency_samples`` completions
        (``n``), so its prompt is encoded once for all draws. Requests are issued
        in ``context_text`` order: neighbours share the longest prompt prefix and
        reuse each other's server-side prompt cache.

        Args:
            items: One ReviewItem per code context to evaluate.

        Returns:
            A ScanFinding for each item, preserving input order.
        """
        if not items:
            return []

        order = sorted(range(len(items)), key=lambda index: items[index].context_text)
        ordered_responses = asyncio.run(
            self.client.chat_batch_samples(
                [self._build_messages(items[index]) for index in order],
                samples=self.self_consistency_samples,
                seeds=[_context_seed(items[index].context_text) for index in order],
                response_format=_review_response_format() if self.structured_output else None,
                max_tokens=self.max_response_tokens,
                concurrency=self.concurrency,
            )
        )
        responses: list[list[str]] = [[] for _ in items]
        for index, item_responses in zip(order, ordered_responses, strict=True):
            responses[index] = item_responses
        return [
            self._build_finding(item, item_responses)
            for item, item_responses in zip(items, responses, strict=True)
        ]

    def _build_messages(self, item: ReviewItem) -> list[ChatMessage]:
        return [
            ChatMessage(role="system", content=_REVIEW_SYSTEM_PROMPT),
            ChatMessage(
                role="user",
                content=_REVIEW_USER_TEMPLATE.format(
                    code=item.context_text,
                    root_static_findings=self._render_root_findings(item),
                ),
            ),
        ]

    def _render_root_findings(self, item: ReviewItem) -> str:
        """Render the ``is_root`` analyzer findings as the prompt's static-findings block.

        Matches the llm4codesec-framework rendering so the prompt sees the same
        format it was evaluated with.
        """
        root_findings = [finding for finding in item.static_findings if finding.is_root]
        if not root_findings:
            return _ROOT_FINDINGS_SEPARATOR + _NO_ROOT_FINDINGS_TEXT

        code_lines = item.context_text.split("\n")
        lines: list[str] = [_ROOT_FINDINGS_HEADER]
        for index, finding in enumerate(root_findings, start=1):
            tags: list[str] = [f"{finding.tool} {finding.rule_id}"]
            if finding.cwe_id is not None:
                tags.append(f"CWE-{finding.cwe_id}")
            if finding.severity:
                tags.append(finding.severity)
            message = " ".join(finding.message.split())
            lines.append(f"{index}. [{' | '.join(tags)}] {message}")
            lines.append(f"   Flagged line: {code_lines[finding.snippet_line - 1].strip()}")
        return _ROOT_FINDINGS_SEPARATOR + "\n".join(lines)

    def _parse_response(self, item: ReviewItem, response: str) -> ScanFinding:
        """Parse a single LLM response into a ScanFinding."""
        return self._build_finding(item, [response])

    def _build_finding(self, item: ReviewItem, responses: list[str]) -> ScanFinding:
        """Combine sampled responses into one ScanFinding by majority vote.

        Ties go to the label seen first (matching llm4codesec-framework). The
        severity, description, CWE and reported root come from the first response
        that agrees with the majority; the root sets the finding's location.

        Args:
            item: The review item these responses correspond to.
            responses: Raw LLM response texts, one per sample.

        Returns:
            A ScanFinding carrying the majority verdict and its vote counts.
        """
        verdicts = [self._parse_verdict(item, response) for response in responses]
        vulnerable_votes = sum(verdict.vulnerable for verdict in verdicts)
        safe_votes = len(verdicts) - vulnerable_votes
        majority = (
            verdicts[0].vulnerable
            if vulnerable_votes == safe_votes
            else vulnerable_votes > safe_votes
        )
        chosen = next(verdict for verdict in verdicts if verdict.vulnerable == majority)
        location = self._reported_root(item, chosen) or ReviewRoot(
            item.file_path, item.line_start, item.line_end
        )

        return ScanFinding(
            root_id=item.root_id,
            file_path=location.file_path,
            line_start=location.line_start,
            line_end=location.line_end,
            static_findings=list(item.static_findings),
            vulnerable=chosen.vulnerable,
            severity=chosen.severity,
            description=chosen.description,
            cwe_id=chosen.cwe_id,
            vulnerable_votes=vulnerable_votes,
            total_votes=len(verdicts),
            context_text=item.context_text,
        )

    def _reported_root(self, item: ReviewItem, verdict: _Verdict) -> ReviewRoot | None:
        """Return the ROOT section the verdict names.

        Falls back to the first root holding an ``is_root`` analyzer finding,
        else the first root, when the index is missing or out of range.
        """
        if not item.roots:
            return None
        if verdict.root is not None and 1 <= verdict.root <= len(item.roots):
            return item.roots[verdict.root - 1]
        return item.roots[self._flagged_root_index(item) - 1]

    def _flagged_root_index(self, item: ReviewItem) -> int:
        """Return the 1-based ROOT section of the first ``is_root`` finding, or 1."""
        flagged = next((finding for finding in item.static_findings if finding.is_root), None)
        if flagged is None:
            return 1
        preceding_lines = item.context_text.split("\n")[: flagged.snippet_line]
        markers = sum(line.startswith(_ROOT_MARKER_PREFIX) for line in preceding_lines)
        return min(max(markers, 1), len(item.roots))

    def _parse_verdict(self, item: ReviewItem, response: str) -> _Verdict:
        """Parse one LLM response into a verdict.

        Uses the last JSON object carrying a ``vulnerable`` key. Falls back to
        ``vulnerable=False`` when the response contains no usable JSON.
        """
        vulnerable = False
        severity: ScanSeverity | None = None
        description: str | None = None
        cwe_id: int | None = None
        root: int | None = None

        for parsed in _verdict_candidates(response):
            raw_vulnerable = parsed.get("vulnerable")
            if isinstance(raw_vulnerable, bool):
                vulnerable = raw_vulnerable
            elif isinstance(raw_vulnerable, int) and raw_vulnerable in (0, 1):
                vulnerable = bool(raw_vulnerable)
            else:
                _LOGGER.warning(
                    "Unexpected 'vulnerable' value %r in LLM response for %s:%d-%d",
                    raw_vulnerable,
                    item.file_path,
                    item.line_start,
                    item.line_end,
                )
                continue

            raw_severity = parsed.get("severity")
            if raw_severity is not None:
                try:
                    severity = ScanSeverity(str(raw_severity).upper())
                except ValueError:
                    _LOGGER.warning("Unknown severity %r in LLM response, ignoring", raw_severity)

            raw_desc = parsed.get("description")
            if isinstance(raw_desc, str) and raw_desc.strip():
                description = raw_desc.strip()

            raw_cwe = parsed.get("cwe_id")
            if isinstance(raw_cwe, int):
                cwe_id = raw_cwe
            elif isinstance(raw_cwe, str) and raw_cwe.isdigit():
                cwe_id = int(raw_cwe)

            raw_root = parsed.get("root")
            if isinstance(raw_root, int) and not isinstance(raw_root, bool):
                root = raw_root

            break
        else:
            _LOGGER.warning(
                "No usable JSON in LLM response for %s:%d-%d; defaulting to not vulnerable",
                item.file_path,
                item.line_start,
                item.line_end,
            )

        return _Verdict(vulnerable, severity, description, cwe_id, root)
