"""OpenAI-compatible chat client usable with vLLM, OpenAI, and Azure endpoints."""

import asyncio
from typing import Any, Final, cast

from openai import AsyncOpenAI, OpenAI
from openai.types.chat import ChatCompletionMessageParam
from pydantic import BaseModel, ConfigDict, Field

from logging_utils import setup_logging

DEFAULT_BASE_URL: Final[str] = "http://localhost:8000/v1"
DEFAULT_TIMEOUT_SECONDS: Final[float] = 60.0
DEFAULT_REPETITION_PENALTY: Final[float] = 1.2

setup_logging()


def _extract_text(completion: Any) -> str:
    """Return assistant content, falling back to vendor-specific reasoning fields.

    vLLM with reasoning parsers (e.g., qwen3) puts thinking under
    ``message.reasoning`` and the final answer under ``message.content``. When
    ``max_tokens`` truncates mid-thinking, ``content`` is ``None`` but
    ``reasoning`` may still contain a parseable answer fragment.
    """

    message = completion.choices[0].message
    content = getattr(message, "content", None)
    if content:
        return content
    payload = message.model_dump() if hasattr(message, "model_dump") else {}
    for key in ("reasoning_content", "reasoning"):
        value = payload.get(key)
        if value:
            return cast(str, value)
    return ""


class ChatMessage(BaseModel):
    """One chat message in a conversation."""

    role: str = Field(..., pattern=r"^(system|user|assistant)$")
    content: str


class OpenAICompatibleClient(BaseModel):
    """Chat client that talks to any OpenAI-compatible HTTP endpoint.

    Works with vLLM, OpenAI, Azure OpenAI, and similar services by varying
    ``base_url``. Supports synchronous single calls and asynchronous batched
    calls via ``asyncio.gather``.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    base_url: str = DEFAULT_BASE_URL
    api_key: str = "not-needed"
    model: str
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    default_max_tokens: int = 512
    default_temperature: float = 0.0
    default_top_p: float | None = None
    default_repetition_penalty: float | None = DEFAULT_REPETITION_PENALTY
    default_top_k: int | None = None
    default_min_p: float | None = None
    default_enable_thinking: bool = True
    """Send ``chat_template_kwargs.enable_thinking=true`` so thinking-capable
    chat templates (e.g. Qwen3) emit ``<think>`` blocks. Set False for
    non-thinking models that reject the kwarg."""

    extra_body: dict[str, Any] | None = None
    """Verbatim ``extra_body`` for every request (e.g. ``chat_template_kwargs``).

    Use this to pass vendor-specific args such as
    ``{"chat_template_kwargs": {"enable_thinking": True}}`` for Qwen3 thinking.
    """

    def _request_kwargs(
        self,
        *,
        response_format: dict[str, Any] | None,
        top_p: float | None,
    ) -> dict[str, Any]:
        kwargs: dict[str, Any] = {}
        if response_format is not None:
            kwargs["response_format"] = response_format
        effective_top_p = self.default_top_p if top_p is None else top_p
        if effective_top_p is not None:
            kwargs["top_p"] = effective_top_p
        extra_body = dict(self.extra_body or {})
        if self.default_repetition_penalty is not None:
            extra_body.setdefault("repetition_penalty", self.default_repetition_penalty)
        if self.default_top_k is not None:
            extra_body.setdefault("top_k", self.default_top_k)
        if self.default_min_p is not None:
            extra_body.setdefault("min_p", self.default_min_p)
        if self.default_enable_thinking:
            chat_template_kwargs = dict(extra_body.get("chat_template_kwargs") or {})
            chat_template_kwargs.setdefault("enable_thinking", True)
            extra_body["chat_template_kwargs"] = chat_template_kwargs
        if extra_body:
            kwargs["extra_body"] = extra_body
        kwargs["seed"] = 42
        return kwargs

    def chat(
        self,
        messages: list[ChatMessage],
        *,
        response_format: dict[str, Any] | None = None,
        max_tokens: int | None = None,
        temperature: float | None = None,
        top_p: float | None = None,
    ) -> str:
        """Send a single chat completion request and return the response text."""

        client = OpenAI(
            base_url=self.base_url,
            api_key=self.api_key,
            timeout=self.timeout_seconds,
        )
        completion = client.chat.completions.create(
            model=self.model,
            messages=cast(
                list[ChatCompletionMessageParam],
                [message.model_dump() for message in messages],
            ),
            max_tokens=max_tokens or self.default_max_tokens,
            temperature=(self.default_temperature if temperature is None else temperature),
            **self._request_kwargs(response_format=response_format, top_p=top_p),
        )
        return _extract_text(completion)

    async def chat_batch(
        self,
        batches: list[list[ChatMessage]],
        *,
        response_format: dict[str, Any] | None = None,
        max_tokens: int | None = None,
        temperature: float | None = None,
        top_p: float | None = None,
        concurrency: int = 8,
    ) -> list[str]:
        """Send many chat completion requests concurrently and return responses."""

        client = AsyncOpenAI(
            base_url=self.base_url,
            api_key=self.api_key,
            timeout=self.timeout_seconds,
        )
        semaphore = asyncio.Semaphore(concurrency)
        request_kwargs = self._request_kwargs(response_format=response_format, top_p=top_p)

        async def _one(messages: list[ChatMessage]) -> str:
            async with semaphore:
                completion = await client.chat.completions.create(
                    model=self.model,
                    messages=cast(
                        list[ChatCompletionMessageParam],
                        [message.model_dump() for message in messages],
                    ),
                    max_tokens=max_tokens or self.default_max_tokens,
                    temperature=(self.default_temperature if temperature is None else temperature),
                    **request_kwargs,
                )
                print(f"Received response: {_extract_text(completion)}")
                return _extract_text(completion)

        return await asyncio.gather(*(_one(messages) for messages in batches))
