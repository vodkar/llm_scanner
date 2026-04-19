"""Unit tests for the Anthropic Message Batches client."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from anthropic.types import Message, TextBlock, Usage
from anthropic.types.messages import (
    MessageBatchErroredResult,
    MessageBatchIndividualResponse,
    MessageBatchSucceededResult,
)
from anthropic.types.shared.api_error_object import APIErrorObject
from anthropic.types.shared.error_response import ErrorResponse

from clients.anthropic_batch import AnthropicBatchClient, BatchPrompt


@pytest.fixture(autouse=True)
def clear_neo4j_database() -> None:
    """Override the global Neo4j autouse fixture for pure unit tests."""

    return None


def _make_succeeded_entry(custom_id: str, text: str) -> MessageBatchIndividualResponse:
    message = Message(
        id="msg_test",
        content=[TextBlock(type="text", text=text)],
        model="claude-opus-4-7",
        role="assistant",
        stop_reason="end_turn",
        stop_sequence=None,
        type="message",
        usage=Usage(
            input_tokens=1,
            output_tokens=1,
            cache_creation_input_tokens=None,
            cache_read_input_tokens=None,
        ),
    )
    return MessageBatchIndividualResponse(
        custom_id=custom_id,
        result=MessageBatchSucceededResult(type="succeeded", message=message),
    )


def _make_errored_entry(custom_id: str) -> MessageBatchIndividualResponse:
    return MessageBatchIndividualResponse(
        custom_id=custom_id,
        result=MessageBatchErroredResult(
            type="errored",
            error=ErrorResponse(
                type="error",
                error=APIErrorObject(type="api_error", message="boom"),
            ),
        ),
    )


def _make_fake_client(
    *,
    batch_id: str,
    statuses: list[str],
    results: list[MessageBatchIndividualResponse],
) -> MagicMock:
    fake_batches = MagicMock()
    fake_batches.create.return_value = SimpleNamespace(
        id=batch_id, processing_status=statuses[0]
    )
    fake_batches.retrieve.side_effect = [
        SimpleNamespace(id=batch_id, processing_status=status) for status in statuses
    ]
    fake_batches.results.return_value = iter(results)

    fake_client = MagicMock()
    fake_client.messages.batches = fake_batches
    return fake_client


def test_submit_and_wait_returns_empty_for_empty_prompts() -> None:
    """No prompts in → no API calls and empty list out."""

    client = AnthropicBatchClient(
        api_key="test", model="claude-opus-4-7", system_prompt="sys"
    )
    with patch("clients.anthropic_batch.Anthropic") as anthropic_cls:
        assert client.submit_and_wait([]) == []
    anthropic_cls.assert_not_called()


def test_submit_and_wait_returns_text_in_prompt_order() -> None:
    """Results must be correlated by custom_id and returned in input order."""

    fake_client = _make_fake_client(
        batch_id="batch_1",
        statuses=["ended"],
        results=[
            _make_succeeded_entry("b", "reply-b"),
            _make_succeeded_entry("a", "reply-a"),
        ],
    )

    with patch("clients.anthropic_batch.Anthropic", return_value=fake_client):
        client = AnthropicBatchClient(
            api_key="test",
            model="claude-opus-4-7",
            system_prompt="sys",
            poll_interval_seconds=0.0,
        )
        results = client.submit_and_wait(
            [
                BatchPrompt(custom_id="a", user_content="q-a"),
                BatchPrompt(custom_id="b", user_content="q-b"),
            ]
        )

    assert [r.custom_id for r in results] == ["a", "b"]
    assert results[0].text == "reply-a"
    assert results[1].text == "reply-b"
    assert all(r.error is None for r in results)


def test_submit_and_wait_records_errors_for_failed_entries() -> None:
    """Non-succeeded entries must populate the error field, not text."""

    fake_client = _make_fake_client(
        batch_id="batch_2",
        statuses=["ended"],
        results=[_make_errored_entry("a")],
    )

    with patch("clients.anthropic_batch.Anthropic", return_value=fake_client):
        client = AnthropicBatchClient(
            api_key="test",
            model="claude-opus-4-7",
            system_prompt="sys",
            poll_interval_seconds=0.0,
        )
        results = client.submit_and_wait(
            [BatchPrompt(custom_id="a", user_content="q-a")]
        )

    assert len(results) == 1
    assert results[0].text is None
    assert results[0].error is not None
    assert "errored" in results[0].error


def test_submit_and_wait_marks_missing_custom_ids() -> None:
    """Prompts with no matching result in the stream must surface an error."""

    fake_client = _make_fake_client(
        batch_id="batch_3",
        statuses=["ended"],
        results=[_make_succeeded_entry("a", "reply-a")],
    )

    with patch("clients.anthropic_batch.Anthropic", return_value=fake_client):
        client = AnthropicBatchClient(
            api_key="test",
            model="claude-opus-4-7",
            system_prompt="sys",
            poll_interval_seconds=0.0,
        )
        results = client.submit_and_wait(
            [
                BatchPrompt(custom_id="a", user_content="q-a"),
                BatchPrompt(custom_id="missing", user_content="q-m"),
            ]
        )

    assert results[0].text == "reply-a"
    assert results[1].text is None
    assert results[1].error is not None


def test_submit_and_wait_polls_until_terminal_status() -> None:
    """Client must poll retrieve() until the batch reaches a terminal status."""

    fake_client = _make_fake_client(
        batch_id="batch_4",
        statuses=["in_progress", "in_progress", "ended"],
        results=[_make_succeeded_entry("a", "reply-a")],
    )

    with patch("clients.anthropic_batch.Anthropic", return_value=fake_client):
        client = AnthropicBatchClient(
            api_key="test",
            model="claude-opus-4-7",
            system_prompt="sys",
            poll_interval_seconds=0.0,
        )
        results = client.submit_and_wait(
            [BatchPrompt(custom_id="a", user_content="q-a")]
        )

    assert results[0].text == "reply-a"
    assert fake_client.messages.batches.retrieve.call_count == 3


def test_submit_and_wait_includes_system_prompt_with_cache_control() -> None:
    """Each request must carry the shared system prompt with ephemeral cache_control."""

    fake_client = _make_fake_client(
        batch_id="batch_5",
        statuses=["ended"],
        results=[_make_succeeded_entry("a", "x")],
    )

    with patch("clients.anthropic_batch.Anthropic", return_value=fake_client):
        client = AnthropicBatchClient(
            api_key="test",
            model="claude-opus-4-7",
            system_prompt="SHARED",
            poll_interval_seconds=0.0,
        )
        client.submit_and_wait([BatchPrompt(custom_id="a", user_content="q")])

    call = fake_client.messages.batches.create.call_args
    request = call.kwargs["requests"][0]
    system = request["params"]["system"]
    assert system[0]["text"] == "SHARED"
    assert system[0]["cache_control"] == {"type": "ephemeral"}
