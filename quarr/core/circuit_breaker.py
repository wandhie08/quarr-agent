"""
circuit_breaker.py - Circuit Breaker

Three-state breaker (CLOSED → OPEN → HALF_OPEN) that prevents cascade failures
when the LLM backend is unhealthy. Failures are counted within a sliding time
window; exceeding the threshold opens the circuit. After a reset timeout, a
single probe is allowed (HALF_OPEN); success closes the circuit, failure reopens.
"""

import threading
import time
from collections import deque
from collections.abc import Awaitable, Callable
from enum import Enum

from quarr.core.exceptions import LLMConnectionError
from quarr.core.logging import get_logger

logger = get_logger("quarr.circuit_breaker")


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    def __init__(
        self,
        threshold: int = 5,
        window: float = 60.0,
        reset_timeout: float = 30.0,
        clock: Callable[[], float] | None = None,
    ):
        self.threshold = threshold
        self.window = window
        self.reset_timeout = reset_timeout
        self._clock = clock or time.monotonic
        self._state = CircuitState.CLOSED
        self._failures: deque = deque()
        self._opened_at = 0.0
        self._lock = threading.Lock()

    @property
    def state(self) -> CircuitState:
        return self._state

    def _transition(self, new_state: CircuitState, reason: str) -> None:
        old = self._state
        self._state = new_state
        logger.warning(
            "circuit_state_change",
            **{"from": old.value, "to": new_state.value, "reason": reason},
        )

    def _prune_failures_locked(self) -> None:
        now = self._clock()
        while self._failures and (now - self._failures[0]) > self.window:
            self._failures.popleft()

    def _before_call_locked(self) -> None:
        now = self._clock()
        if self._state == CircuitState.OPEN:
            if (now - self._opened_at) >= self.reset_timeout:
                self._transition(CircuitState.HALF_OPEN, "reset_timeout_elapsed")
            else:
                raise LLMConnectionError(
                    "Circuit breaker is OPEN",
                    context={
                        "state": "open",
                        "retry_in": round(self.reset_timeout - (now - self._opened_at), 2),
                    },
                )

    def _on_success_locked(self) -> None:
        if self._state == CircuitState.HALF_OPEN:
            self._transition(CircuitState.CLOSED, "probe_succeeded")
        self._failures.clear()

    def _on_failure_locked(self) -> None:
        now = self._clock()
        if self._state == CircuitState.HALF_OPEN:
            self._opened_at = now
            self._transition(CircuitState.OPEN, "probe_failed")
            return
        self._failures.append(now)
        self._prune_failures_locked()
        if len(self._failures) >= self.threshold:
            self._opened_at = now
            self._transition(CircuitState.OPEN, "threshold_exceeded")

    async def call(self, coro_fn: Callable[..., Awaitable], *args, **kwargs):
        """Execute an async function through the breaker."""
        with self._lock:
            self._before_call_locked()

        try:
            result = await coro_fn(*args, **kwargs)
        except Exception:
            with self._lock:
                self._on_failure_locked()
            raise
        else:
            with self._lock:
                self._on_success_locked()
            return result
