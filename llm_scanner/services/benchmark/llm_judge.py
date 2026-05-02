"""LLM-as-judge scoring service for context benchmark samples."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Final

from pydantic import BaseModel, ConfigDict, Field

from clients.openai_compatible import ChatMessage, OpenAICompatibleClient
from models.benchmark.benchmark import BenchmarkDataset, BenchmarkSample

_LOGGER: Final[logging.Logger] = logging.getLogger(__name__)

JUDGE_SYSTEM_PROMPT: Final[str] = (
    "You are a security engineer reviewing assembled Python code context. "
    "Think step by step about whether the code contains a genuine, exploitable "
    "vulnerability: identify untrusted sources, sinks, sanitizers, and any data "
    "flow connecting them. After you have finished reasoning, output "
    "final line containing strict JSON of the form "
    '{"vulnerable": true} or {"vulnerable": false}.'
)

USER_PROMPT_TEMPLATE: Final[str] = (
    "Analyze the following Python code and decide whether it is genuinely "
    "vulnerable. Reason carefully, then end with the required JSON verdict on "
    "its own final line.\n\n<code>\n{code}\n</code>"
)

_JSON_OBJECT_PATTERN: Final[re.Pattern[str]] = re.compile(r"\{.*?\}", re.DOTALL)


class LLMJudgeResult(BaseModel):
    """Outcome of scoring a benchmark dataset with an LLM judge."""

    model_config = ConfigDict(frozen=True)

    accuracy: float = Field(..., ge=0.0, le=1.0)
    predictions: dict[str, int] = Field(default_factory=dict)
    invalid_responses: int = Field(default=0, ge=0)


class LLMJudgeService(BaseModel):
    """Score a benchmark dataset by asking an LLM whether each sample is vulnerable."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    client: OpenAICompatibleClient
    concurrency: int = 8
    max_response_tokens: int = 64

    def score_dataset(self, dataset: BenchmarkDataset) -> LLMJudgeResult:
        """Return accuracy of the judge's predictions against labeled samples."""

        if not dataset.samples:
            return LLMJudgeResult(accuracy=0.0)

        batches = [self._build_messages(sample) for sample in dataset.samples]
        responses = asyncio.run(
            self.client.chat_batch(
                batches,
                max_tokens=self.max_response_tokens,
                concurrency=self.concurrency,
            )
        )

        predictions: dict[str, int] = {}
        correct = 0
        invalid = 0
        for sample, response in zip(dataset.samples, responses, strict=True):
            prediction = self._parse_prediction(response)
            if prediction is None:
                invalid += 1
                continue
            predictions[sample.id] = prediction
            if prediction == sample.label:
                correct += 1

        accuracy = correct / len(dataset.samples)
        return LLMJudgeResult(
            accuracy=accuracy,
            predictions=predictions,
            invalid_responses=invalid,
        )

    def _build_messages(self, sample: BenchmarkSample) -> list[ChatMessage]:
        return [
            ChatMessage(role="system", content=JUDGE_SYSTEM_PROMPT),
            ChatMessage(role="user", content=USER_PROMPT_TEMPLATE.format(code=sample.code)),
        ]

    @staticmethod
    def _parse_prediction(response: str) -> int | None:
        """Extract a binary prediction from a judge's JSON response."""

        snippet = response[-400:] if len(response) > 400 else response
        matches = _JSON_OBJECT_PATTERN.findall(response)
        if not matches:
            _LOGGER.warning("Judge response missing JSON object: %r", snippet)
            return None
        for raw in reversed(matches):
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if not isinstance(parsed, dict) or "vulnerable" not in parsed:
                continue
            value = parsed["vulnerable"]
            if isinstance(value, bool):
                return 1 if value else 0
            if isinstance(value, int) and value in (0, 1):
                return value
        _LOGGER.warning("Judge response has no usable vulnerable JSON: %r", snippet)
        return None
