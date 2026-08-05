"""Shared start-rate limiter for host scan pipelines."""

from __future__ import annotations

import threading
import time

from core.runtime.cancellation import CancellationToken


class RateLimiter:
    """Space host pipeline starts evenly across time."""

    def __init__(self, rate_per_second: float) -> None:
        if rate_per_second <= 0:
            raise ValueError("rate_per_second must be positive")
        self._interval = 1.0 / rate_per_second
        self._next_start = 0.0
        self._lock = threading.Lock()

    def wait(self, token: CancellationToken | None = None) -> None:
        with self._lock:
            now = time.monotonic()
            scheduled = max(now, self._next_start)
            self._next_start = scheduled + self._interval

        delay = scheduled - now
        if delay <= 0:
            return
        if token is not None:
            token.wait(delay)
            token.raise_if_cancelled()
        else:
            time.sleep(delay)
