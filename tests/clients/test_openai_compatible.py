"""Unit tests for the OpenAI-compatible chat client."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from clients.openai_compatible import ChatMessage, OpenAICompatibleClient


@pytest.fixture(autouse=True)
def clear_neo4j_database() -> None:
    """Override the global Neo4j autouse fixture for pure unit tests."""

    return None


def _make_completion(text: str) -> SimpleNamespace:
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=text))])


def test_chat_returns_content_from_openai_sdk() -> None:
    """Synchronous chat must return the first choice's content field."""

    fake_client = MagicMock()
    fake_client.chat.completions.create.return_value = _make_completion("vulnerable")

    with patch("clients.openai_compatible.OpenAI", return_value=fake_client):
        client = OpenAICompatibleClient(model="test-model")
        result = client.chat([ChatMessage(role="user", content="Is this vulnerable?")])

    assert result == "vulnerable"
    call = fake_client.chat.completions.create.call_args
    assert call.kwargs["model"] == "test-model"
    assert call.kwargs["messages"] == [{"role": "user", "content": "Is this vulnerable?"}]


def test_chat_forwards_response_format_when_provided() -> None:
    """When response_format is passed, it should be forwarded to the SDK call."""

    fake_client = MagicMock()
    fake_client.chat.completions.create.return_value = _make_completion("{}")

    with patch("clients.openai_compatible.OpenAI", return_value=fake_client):
        client = OpenAICompatibleClient(model="test-model")
        client.chat(
            [ChatMessage(role="user", content="hi")],
            response_format={"type": "json_object"},
        )

    call = fake_client.chat.completions.create.call_args
    assert call.kwargs["response_format"] == {"type": "json_object"}


def test_chat_adds_default_repetition_penalty_to_extra_body() -> None:
    """Chat requests must include the default repetition penalty via extra_body."""

    fake_client = MagicMock()
    fake_client.chat.completions.create.return_value = _make_completion("ok")

    with patch("clients.openai_compatible.OpenAI", return_value=fake_client):
        client = OpenAICompatibleClient(model="test-model")
        client.chat([ChatMessage(role="user", content="hi")])

    call = fake_client.chat.completions.create.call_args
    assert call.kwargs["extra_body"] == {
        "repetition_penalty": 1.2,
        "chat_template_kwargs": {"enable_thinking": True},
    }


def test_chat_preserves_explicit_extra_body_repetition_penalty() -> None:
    """Caller-provided extra_body repetition penalty should take precedence."""

    fake_client = MagicMock()
    fake_client.chat.completions.create.return_value = _make_completion("ok")

    with patch("clients.openai_compatible.OpenAI", return_value=fake_client):
        client = OpenAICompatibleClient(
            model="test-model",
            extra_body={
                "chat_template_kwargs": {"enable_thinking": True},
                "repetition_penalty": 1.5,
            },
        )
        client.chat([ChatMessage(role="user", content="hi")])

    call = fake_client.chat.completions.create.call_args
    assert call.kwargs["extra_body"] == {
        "chat_template_kwargs": {"enable_thinking": True},
        "repetition_penalty": 1.5,
    }


def test_chat_omits_response_format_when_none() -> None:
    """When response_format is None, it must not be sent at all."""

    fake_client = MagicMock()
    fake_client.chat.completions.create.return_value = _make_completion("ok")

    with patch("clients.openai_compatible.OpenAI", return_value=fake_client):
        client = OpenAICompatibleClient(model="test-model")
        client.chat([ChatMessage(role="user", content="hi")])

    call = fake_client.chat.completions.create.call_args
    assert "response_format" not in call.kwargs


def test_chat_batch_runs_concurrent_requests() -> None:
    """Async batch must return one response per input prompt."""

    fake_async_client = MagicMock()
    fake_async_client.chat.completions.create = AsyncMock(
        side_effect=[_make_completion(f"reply-{idx}") for idx in range(3)]
    )

    with patch("clients.openai_compatible.AsyncOpenAI", return_value=fake_async_client):
        client = OpenAICompatibleClient(model="test-model")
        batches = [[ChatMessage(role="user", content=f"question-{idx}")] for idx in range(3)]
        results = asyncio.run(client.chat_batch(batches))

    assert results == ["reply-0", "reply-1", "reply-2"]
    assert fake_async_client.chat.completions.create.await_count == 3
    for call in fake_async_client.chat.completions.create.await_args_list:
        assert call.kwargs["extra_body"] == {
            "repetition_penalty": 1.2,
            "chat_template_kwargs": {"enable_thinking": True},
        }
