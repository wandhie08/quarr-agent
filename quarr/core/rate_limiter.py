"""
rate_limiter.py - Token Bucket Rate Limiter

Thread-safe token bucket with an async acquire(). Refills continuously based on
elapsed time. When a token is unavailable, acquire() waits; if the required wait
exceeds max_wait, it raises LLMRateLimitError instead of blocking indefinitely.
"""

import asyncio
import threading
import time
from collections.abc import Callable

from quarr.core.exceptions import LLMRateLimitError
from quarr.core.logging import get_logger

logger = get_logger("quarr.rate_limiter")


class TokenBucket:
    def __init__(
        self,
        rate_per_minute: int = 60,
        burst: int = 10,
        clock: Callable[[], float] | None = None,
        sleep=asyncio.sleep,
    ):
        if rate_per_minute <= 0:
            raise ValueError("rate_per_minute must be > 0")
        if burst <= 0:
            raise ValueError("burst must be > 0")
        self.rate_per_second = rate_per_minute / 60.0
        self.burst = float(burst)
        self._tokens = float(burst)
        self._clock = clock or time.monotonic
        self._sleep = sleep
        self._last = self._clock()
        self._lock = threading.Lock()

    def _refill_locked(self) -> None:
        now = self._clock()
        elapsed = now - self._last
        if elapsed > 0:
            self._tokens = min(self.burst, self._tokens + elapsed * self.rate_per_second)
            self._last = now

    def _time_until_token_locked(self) -> float:
        """Seconds until at least one token is available (0 if available now)."""
        self._refill_locked()
        if self._tokens >= 1.0:
            return 0.0
        needed = 1.0 - self._tokens
        return needed / self.rate_per_second

    async def acquire(self, max_wait: float = 30.0) -> None:
        """Consume one token, waiting up to max_wait seconds if necessary."""
        with self._lock:
            wait = self._time_until_token_locked()
            if wait > max_wait:
                logger.debug("rate_limit_exceeded", wait=round(wait, 2), max_wait=max_wait)
                raise LLMRateLimitError(
                    "Rate limit wait exceeds maximum",
                    context={"wait": round(wait, 2), "max_wait": max_wait},
                )
            if wait == 0.0:
                self._tokens -= 1.0
                logger.debug("rate_limit_acquire", tokens=round(self._tokens, 2), wait=0)
                return

        # Wait outside the lock, then re-acquire.
        logger.debug("rate_limit_wait", wait=round(wait, 2))
        await self._sleep(wait)
        with self._lock:
            self._refill_locked()
            # After waiting, a token should be available; consume defensively.
            self._tokens = max(0.0, self._tokens - 1.0)
            logger.debug("rate_limit_acquire", tokens=round(self._tokens, 2), wait=round(wait, 2))
