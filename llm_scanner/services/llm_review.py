"""LLM-based code review service for the CI scanner pipeline."""

import asyncio
import json
import logging
import re
from pathlib import Path
from typing import Final, NamedTuple

from pydantic import BaseModel, ConfigDict

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
    "insufficient, classify the code as not vulnerable. False alarms are costly."
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
    '"cwe_id" (integer CWE number, or null).'
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

_JSON_OBJECT_PATTERN: Final[re.Pattern[str]] = re.compile(r"\{[^{}]*\}", re.DOTALL)


class ReviewItem(NamedTuple):
    """Inputs for one LLM review request."""

    root_id: str
    file_path: Path
    line_start: int
    line_end: int
    context_text: str
    static_findings: list[StaticFinding]
    """Analyzer findings resolved into ``context_text``; ``is_root`` ones go into the prompt."""


class LLMCodeReviewService(BaseModel):
    """Review assembled code contexts with an LLM and return structured findings.

    Each item in the batch is sent as an independent chat completion request via
    ``OpenAICompatibleClient.chat_batch()``.  Responses are parsed for a
    terminal JSON object; on parse failure the finding defaults to
    ``vulnerable=False`` and a warning is logged.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    client: OpenAICompatibleClient
    concurrency: int = 8
    max_response_tokens: int = 2048

    def review(self, items: list[ReviewItem]) -> list[ScanFinding]:
        """Send all items to the LLM and return a structured ScanFinding for each.

        Args:
            items: One ReviewItem per code context to evaluate.

        Returns:
            A ScanFinding for each item, preserving input order.
        """
        if not items:
            return []

        batches = [self._build_messages(item) for item in items]
        responses = asyncio.run(
            self.client.chat_batch(
                batches,
                max_tokens=self.max_response_tokens,
                concurrency=self.concurrency,
            )
        )
        return [
            self._parse_response(item, response)
            for item, response in zip(items, responses, strict=True)
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
        """Parse the LLM response JSON into a ScanFinding.

        Falls back to ``vulnerable=False`` when the response contains no usable JSON.

        Args:
            item: The review item this response corresponds to.
            response: Raw LLM response text.

        Returns:
            A ScanFinding populated from the parsed JSON verdict.
        """
        snippet = response[-500:] if len(response) > 500 else response
        matches = _JSON_OBJECT_PATTERN.findall(snippet)

        vulnerable = False
        severity: ScanSeverity | None = None
        description: str | None = None
        cwe_id: int | None = None

        for raw in reversed(matches):
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if not isinstance(parsed, dict) or "vulnerable" not in parsed:
                continue

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

            break
        else:
            _LOGGER.warning(
                "No usable JSON in LLM response for %s:%d-%d; defaulting to not vulnerable",
                item.file_path,
                item.line_start,
                item.line_end,
            )

        return ScanFinding(
            root_id=item.root_id,
            file_path=item.file_path,
            line_start=item.line_start,
            line_end=item.line_end,
            static_findings=list(item.static_findings),
            vulnerable=vulnerable,
            severity=severity,
            description=description,
            cwe_id=cwe_id,
            context_text=item.context_text,
        )
