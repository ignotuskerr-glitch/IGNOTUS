"""Cooperative cancellation and global scan deadlines."""

from __future__ import annotations

import threading
import time


class ScanCancelled(RuntimeError):
    """Raised when a scan is cancelled or reaches its deadline."""


class CancellationToken:
    """Thread-safe cancellation token shared by every host worker."""

    def __init__(self, timeout_seconds: float | None = None) -> None:
        self._event = threading.Event()
        self._deadline = (
            time.monotonic() + timeout_seconds if timeout_seconds is not None else None
        )

    @property
    def cancelled(self) -> bool:
        return self._event.is_set() or (
            self._deadline is not None and time.monotonic() >= self._deadline
        )

    @property
    def remaining(self) -> float | None:
        if self._deadline is None:
            return None
        return max(0.0, self._deadline - time.monotonic())

    def cancel(self) -> None:
        self._event.set()

    def raise_if_cancelled(self) -> None:
        if self.cancelled:
            raise ScanCancelled("scan cancelado ou prazo global excedido")

    def wait(self, seconds: float) -> bool:
        """Wait cooperatively; return True when cancellation was requested."""
        remaining = self.remaining
        if remaining is not None:
            seconds = min(seconds, remaining)
        self._event.wait(max(0.0, seconds))
        return self.cancelled
