"""LLM-as-judge scoring service for context benchmark samples."""

import asyncio
import hashlib
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
    "The code is split into sections: each '# ===== ROOT i/N' section is code under "
    "analysis, and the '# ----- CONTEXT for ROOT i' section after it is reference-only "
    "code related to that root (callers, callees, definitions). Judge only the ROOT "
    "code; use its CONTEXT to trace inputs and called behavior. "
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
_SAMPLING_SEED: Final[int] = 42
_SEED_MODULUS: Final[int] = 2**31


def _sample_seed(code: str) -> int:
    """Derive a stable per-sample seed so identical contexts draw identical votes."""

    digest = hashlib.sha256(f"{_SAMPLING_SEED}|{code}".encode()).digest()
    return int.from_bytes(digest[:8], "big") % _SEED_MODULUS


class LLMJudgeResult(BaseModel):
    """Outcome of scoring a benchmark dataset with an LLM judge."""

    model_config = ConfigDict(frozen=True)

    accuracy: float = Field(..., ge=0.0, le=1.0)
    fnr: float = Field(default=0.0, ge=0.0, le=1.0)
    predictions: dict[str, int] = Field(default_factory=dict)
    invalid_responses: int = Field(default=0, ge=0)


class LLMJudgeService(BaseModel):
    """Score a benchmark dataset by asking an LLM whether each sample is vulnerable."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    client: OpenAICompatibleClient
    concurrency: int = 8
    max_response_tokens: int = 64
    self_consistency_samples: int = Field(default=1, ge=1)
    """Completions drawn per sample; the prediction is their majority vote."""

    def score_dataset(self, dataset: BenchmarkDataset) -> LLMJudgeResult:
        """Return accuracy and FNR of the judge's predictions against labeled samples.

        With ``self_consistency_samples > 1`` each sample is sent once with
        ``n`` completions under a seed derived from its code, and the
        prediction is the majority of the parseable votes.
        """

        if not dataset.samples:
            return LLMJudgeResult(accuracy=0.0)

        predictions: dict[str, int] = {}
        correct = 0
        invalid = 0
        false_negatives = 0
        actual_positives = sum(1 for s in dataset.samples if s.label == 1)
        for sample, responses in zip(dataset.samples, self._sample_responses(dataset), strict=True):
            prediction = self._vote([self._parse_prediction(response) for response in responses])
            if prediction is None:
                invalid += 1
                continue
            predictions[sample.id] = prediction
            if prediction == sample.label:
                correct += 1
            if sample.label == 1 and prediction == 0:
                false_negatives += 1

        accuracy = correct / len(dataset.samples)
        fnr = false_negatives / actual_positives if actual_positives > 0 else 0.0
        return LLMJudgeResult(
            accuracy=accuracy,
            fnr=fnr,
            predictions=predictions,
            invalid_responses=invalid,
        )

    def _sample_responses(self, dataset: BenchmarkDataset) -> list[list[str]]:
        """Return the judge's raw responses, ``self_consistency_samples`` per sample."""

        batches = [self._build_messages(sample) for sample in dataset.samples]
        if self.self_consistency_samples == 1:
            responses = asyncio.run(
                self.client.chat_batch(
                    batches,
                    max_tokens=self.max_response_tokens,
                    concurrency=self.concurrency,
                )
            )
            return [[response] for response in responses]
        return asyncio.run(
            self.client.chat_batch_samples(
                batches,
                samples=self.self_consistency_samples,
                seeds=[_sample_seed(sample.code) for sample in dataset.samples],
                max_tokens=self.max_response_tokens,
                concurrency=self.concurrency,
            )
        )

    def _vote(self, votes: list[int | None]) -> int | None:
        """Return the majority of the parseable votes; ties go to the first one.

        Returns ``None`` when no vote is parseable.
        """

        valid = [vote for vote in votes if vote is not None]
        if not valid:
            return None
        positives = sum(valid)
        negatives = len(valid) - positives
        if positives == negatives:
            return valid[0]
        return 1 if positives > negatives else 0

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
