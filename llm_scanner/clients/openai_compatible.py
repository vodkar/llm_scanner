"""OpenAI-compatible chat client usable with vLLM, OpenAI, and Azure endpoints."""

from __future__ import annotations

import asyncio
from typing import Any, Final, cast

from openai import AsyncOpenAI, OpenAI
from openai.types.chat import ChatCompletionMessageParam
from pydantic import BaseModel, ConfigDict, Field

DEFAULT_BASE_URL: Final[str] = "http://localhost:8000/v1"
DEFAULT_TIMEOUT_SECONDS: Final[float] = 60.0


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

    def chat(
        self,
        messages: list[ChatMessage],
        *,
        response_format: dict[str, Any] | None = None,
        max_tokens: int | None = None,
        temperature: float | None = None,
    ) -> str:
        """Send a single chat completion request and return the response text."""

        client = OpenAI(
            base_url=self.base_url,
            api_key=self.api_key,
            timeout=self.timeout_seconds,
        )
        extra_kwargs: dict[str, Any] = {}
        if response_format is not None:
            extra_kwargs["response_format"] = response_format
        completion = client.chat.completions.create(
            model=self.model,
            messages=cast(
                list[ChatCompletionMessageParam],
                [message.model_dump() for message in messages],
            ),
            max_tokens=max_tokens or self.default_max_tokens,
            temperature=(
                self.default_temperature if temperature is None else temperature
            ),
            **extra_kwargs,
        )
        return _extract_text(completion)

    async def chat_batch(
        self,
        batches: list[list[ChatMessage]],
        *,
        response_format: dict[str, Any] | None = None,
        max_tokens: int | None = None,
        temperature: float | None = None,
        concurrency: int = 8,
    ) -> list[str]:
        """Send many chat completion requests concurrently and return responses."""

        client = AsyncOpenAI(
            base_url=self.base_url,
            api_key=self.api_key,
            timeout=self.timeout_seconds,
        )
        semaphore = asyncio.Semaphore(concurrency)
        extra_kwargs: dict[str, Any] = {}
        if response_format is not None:
            extra_kwargs["response_format"] = response_format

        async def _one(messages: list[ChatMessage]) -> str:
            async with semaphore:
                completion = await client.chat.completions.create(
                    model=self.model,
                    messages=cast(
                        list[ChatCompletionMessageParam],
                        [message.model_dump() for message in messages],
                    ),
                    max_tokens=max_tokens or self.default_max_tokens,
                    temperature=(
                        self.default_temperature if temperature is None else temperature
                    ),
                    **extra_kwargs,
                )
                return _extract_text(completion)

        return await asyncio.gather(*(_one(messages) for messages in batches))
