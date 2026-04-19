"""Unit tests for the LLM-as-judge benchmark scoring service."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from clients.openai_compatible import OpenAICompatibleClient
from models.benchmark.benchmark import (
    BenchmarkDataset,
    BenchmarkMetadata,
    BenchmarkSample,
    CleanVulSampleMetadata,
)
from services.benchmark.llm_judge import LLMJudgeService


@pytest.fixture(autouse=True)
def clear_neo4j_database() -> None:
    """Override the global Neo4j autouse fixture for pure unit tests."""

    return None


def _make_sample(sample_id: str, label: int, code: str = "print('x')") -> BenchmarkSample:
    return BenchmarkSample(
        id=sample_id,
        code=code,
        label=label,
        metadata=CleanVulSampleMetadata(
            commit_url="https://example.com/commit/abc",
            description="",
            cwe_number=79,
        ),
        cwe_types=[],
        severity="low",
    )


def _make_dataset(samples: list[BenchmarkSample]) -> BenchmarkDataset:
    return BenchmarkDataset(
        metadata=BenchmarkMetadata(
            name="unit-test",
            task_type="vulnerability-detection",
            total_samples=len(samples),
        ),
        samples=samples,
    )


def _make_client_with_responses(responses: list[str]) -> OpenAICompatibleClient:
    client = MagicMock(spec=OpenAICompatibleClient)
    client.chat_batch = AsyncMock(return_value=responses)
    return client


def test_score_dataset_computes_accuracy_across_correct_and_incorrect() -> None:
    """Accuracy must equal (#correct / #samples) for valid predictions."""

    dataset = _make_dataset(
        [
            _make_sample("a", label=1),
            _make_sample("b", label=0),
            _make_sample("c", label=1),
            _make_sample("d", label=0),
        ]
    )
    client = _make_client_with_responses(
        [
            '{"vulnerable": true}',   # correct (label=1)
            '{"vulnerable": false}',  # correct (label=0)
            '{"vulnerable": false}',  # wrong   (label=1)
            '{"vulnerable": false}',  # correct (label=0)
        ]
    )

    service = LLMJudgeService(client=client)
    result = service.score_dataset(dataset)

    assert result.accuracy == pytest.approx(0.75)
    assert result.predictions == {"a": 1, "b": 0, "c": 0, "d": 0}
    assert result.invalid_responses == 0


def test_score_dataset_counts_invalid_responses_and_excludes_them_from_predictions() -> None:
    """Invalid JSON responses must increment invalid_responses but never predictions."""

    dataset = _make_dataset(
        [
            _make_sample("a", label=1),
            _make_sample("b", label=0),
        ]
    )
    client = _make_client_with_responses(
        [
            "this is not json at all",
            '{"not_vulnerable_key": true}',
        ]
    )

    service = LLMJudgeService(client=client)
    result = service.score_dataset(dataset)

    assert result.accuracy == 0.0
    assert result.predictions == {}
    assert result.invalid_responses == 2


def test_score_dataset_returns_zero_for_empty_dataset() -> None:
    """Scoring an empty dataset must not error and must return accuracy 0.0."""

    dataset = _make_dataset([])
    client = _make_client_with_responses([])

    service = LLMJudgeService(client=client)
    result = service.score_dataset(dataset)

    assert result.accuracy == 0.0
    assert result.predictions == {}
    assert result.invalid_responses == 0
    client.chat_batch.assert_not_called()


def test_score_dataset_accepts_integer_predictions_as_well_as_booleans() -> None:
    """Judge responses of the form {\"vulnerable\": 1} must parse to prediction 1."""

    dataset = _make_dataset(
        [
            _make_sample("a", label=1),
            _make_sample("b", label=0),
        ]
    )
    client = _make_client_with_responses(
        [
            '{"vulnerable": 1}',
            '{"vulnerable": 0}',
        ]
    )

    service = LLMJudgeService(client=client)
    result = service.score_dataset(dataset)

    assert result.accuracy == 1.0
    assert result.predictions == {"a": 1, "b": 0}


def test_score_dataset_tolerates_trailing_prose_around_json() -> None:
    """A valid JSON object embedded in prose must still be parsed correctly."""

    dataset = _make_dataset([_make_sample("a", label=1)])
    client = _make_client_with_responses(
        ['Sure! Here is my verdict: {"vulnerable": true} — thanks.']
    )

    service = LLMJudgeService(client=client)
    result = service.score_dataset(dataset)

    assert result.accuracy == 1.0
    assert result.predictions == {"a": 1}
    assert result.invalid_responses == 0


def test_score_dataset_forwards_json_response_format_to_client() -> None:
    """The judge must request JSON mode from the chat client."""

    dataset = _make_dataset([_make_sample("a", label=1)])
    client = _make_client_with_responses(['{"vulnerable": true}'])

    service = LLMJudgeService(client=client, concurrency=3, max_response_tokens=32)
    service.score_dataset(dataset)

    call = client.chat_batch.await_args
    assert call.kwargs["response_format"] == {"type": "json_object"}
    assert call.kwargs["concurrency"] == 3
    assert call.kwargs["max_tokens"] == 32
