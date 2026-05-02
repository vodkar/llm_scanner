"""Anthropic Message Batches client with prompt caching on the system prompt.

Wraps the official ``anthropic`` SDK's batches API for cost-sensitive scoring
runs (50% discount vs. online calls). Callers submit a list of prompts and
receive the model's text responses correlated by ``custom_id``.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Final, cast

from anthropic import Anthropic
from anthropic.types import TextBlock
from anthropic.types.messages import MessageBatchSucceededResult
from anthropic.types.messages.batch_create_params import Request
from pydantic import BaseModel, ConfigDict, Field

_LOGGER: Final[logging.Logger] = logging.getLogger(__name__)

_TERMINAL_STATUSES: Final[frozenset[str]] = frozenset({"ended", "canceled", "expired"})


class BatchPrompt(BaseModel):
    """A single request to send inside a batch."""

    model_config = ConfigDict(frozen=True)

    custom_id: str = Field(..., min_length=1, max_length=64)
    user_content: str
    max_tokens: int = 1024
    temperature: float = 0.0


class BatchResult(BaseModel):
    """One message's text content (or error) from the batch."""

    model_config = ConfigDict(frozen=True)

    custom_id: str
    text: str | None = None
    error: str | None = None


class AnthropicBatchClient(BaseModel):
    """Submit and poll Anthropic Message Batches.

    Uses prompt caching on the shared system prompt so that large batches only
    pay the full system-prompt cost once per 5-minute cache window.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    api_key: str
    model: str
    system_prompt: str
    poll_interval_seconds: float = 30.0
    timeout_seconds: float = 24 * 60 * 60.0

    def submit_and_wait(self, prompts: list[BatchPrompt]) -> list[BatchResult]:
        """Submit a batch, poll until it completes, and return per-request results.

        Args:
            prompts: One ``BatchPrompt`` per request. ``custom_id`` values must be unique.

        Returns:
            One ``BatchResult`` per input prompt, in the same order.
        """

        if not prompts:
            return []

        client = Anthropic(api_key=self.api_key)
        requests = self._build_requests(prompts)
        batch = client.messages.batches.create(requests=requests)
        _LOGGER.info("created Anthropic batch id=%s count=%d", batch.id, len(prompts))

        deadline = time.monotonic() + self.timeout_seconds
        while True:
            batch = client.messages.batches.retrieve(batch.id)
            if batch.processing_status in _TERMINAL_STATUSES:
                break
            if time.monotonic() > deadline:
                raise TimeoutError(
                    f"Anthropic batch {batch.id} did not finish within {self.timeout_seconds:.0f}s"
                )
            time.sleep(self.poll_interval_seconds)

        return self._collect_results(client, batch.id, prompts)

    def _build_requests(self, prompts: list[BatchPrompt]) -> list[Request]:
        system_blocks: list[dict[str, Any]] = [
            {
                "type": "text",
                "text": self.system_prompt,
                "cache_control": {"type": "ephemeral"},
            }
        ]
        requests: list[Request] = []
        for prompt in prompts:
            params: dict[str, Any] = {
                "model": self.model,
                "max_tokens": prompt.max_tokens,
                "temperature": prompt.temperature,
                "system": system_blocks,
                "messages": [{"role": "user", "content": prompt.user_content}],
            }
            requests.append(cast(Request, {"custom_id": prompt.custom_id, "params": params}))
        return requests

    @staticmethod
    def _collect_results(
        client: Anthropic, batch_id: str, prompts: list[BatchPrompt]
    ) -> list[BatchResult]:
        by_id: dict[str, BatchResult] = {}
        for entry in client.messages.batches.results(batch_id):
            custom_id = entry.custom_id
            result = entry.result
            if isinstance(result, MessageBatchSucceededResult):
                text_parts = [
                    block.text for block in result.message.content if isinstance(block, TextBlock)
                ]
                by_id[custom_id] = BatchResult(custom_id=custom_id, text="".join(text_parts))
            else:
                by_id[custom_id] = BatchResult(
                    custom_id=custom_id, error=f"batch entry status: {result.type}"
                )

        ordered: list[BatchResult] = []
        for prompt in prompts:
            if prompt.custom_id in by_id:
                ordered.append(by_id[prompt.custom_id])
            else:
                ordered.append(
                    BatchResult(
                        custom_id=prompt.custom_id,
                        error="no result returned for custom_id",
                    )
                )
        return ordered
