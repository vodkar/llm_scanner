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

_LOGGER: Final[logging.Logger] = logging.getLogger(__name__)

_REVIEW_SYSTEM_PROMPT: Final[str] = (
    "You are a security engineer performing a code security review in a CI pipeline. "
    "Given assembled Python code context, analyze whether it contains a genuine, "
    "exploitable vulnerability. Think step by step about untrusted input sources, "
    "sinks, sanitizers, and data flow connecting them. "
    "After you have finished reasoning, output a JSON object on its own final line "
    'with exactly these keys: "vulnerable" (bool), "severity" '
    '("LOW", "MEDIUM", "HIGH", or "CRITICAL", or null if not vulnerable), '
    '"description" (string describing the issue, or null if not vulnerable), '
    '"cwe_id" (integer CWE number, or null).'
)

_REVIEW_USER_TEMPLATE: Final[str] = (
    "Review the following Python code for security vulnerabilities:\n\n"
    "<code>\n{context_text}\n</code>"
)

_JSON_OBJECT_PATTERN: Final[re.Pattern[str]] = re.compile(r"\{[^{}]*\}", re.DOTALL)


class ReviewItem(NamedTuple):
    """Inputs for one LLM review request."""

    root_id: str
    file_path: Path
    line_start: int
    line_end: int
    context_text: str
    static_tool_messages: list[str]


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
                content=_REVIEW_USER_TEMPLATE.format(context_text=item.context_text),
            ),
        ]

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
            static_tool_messages=list(item.static_tool_messages),
            vulnerable=vulnerable,
            severity=severity,
            description=description,
            cwe_id=cwe_id,
            context_text=item.context_text,
        )
