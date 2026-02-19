"""Utility decorators and helpers."""

from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from time import perf_counter
from typing import ParamSpec, TypeVar

P = ParamSpec("P")
R = TypeVar("R")


def timed[**P, R](func: Callable[P, R]) -> Callable[P, R]:
    """Print function execution time.

    Args:
        func: Function to wrap.

    Returns:
        Wrapped function that prints execution time in seconds.
    """

    @wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        start_time = perf_counter()
        result = func(*args, **kwargs)
        duration_seconds = perf_counter() - start_time
        print(f"{func.__qualname__} executed in {duration_seconds:.4f}s")
        return result

    return wrapper
