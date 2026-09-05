"""
target_throttle.py - Per-target request throttling (scope/program compliance).

Bug-bounty and professional engagements often require respecting a target's
rate limits ("no more than N requests/sec", "be gentle"). This provides a
synchronous, thread-safe throttle keyed by target host, so tool handlers (which
are synchronous) can pace their requests per target.

Usage:
    from quarr.core.target_throttle import get_throttle
    get_throttle().wait("target.com")   # blocks just enough to honor the rate

Configure globally via env:
    QUARR_TARGET_RPS   — max requests per second per target (default: unlimited)
"""

from __future__ import annotations

import os
import threading
import time


class TargetRateLimiter:
    """Thread-safe per-target minimum-interval throttle.

    Enforces at most `rps` requests/second for each distinct target by sleeping
    the caller until the minimum interval since that target's last request has
    elapsed. rps<=0 means no limit (no-op).
    """

    def __init__(self, rps: float = 0.0, clock=time.monotonic, sleep=time.sleep):
        self.rps = float(rps)
        self._min_interval = (1.0 / self.rps) if self.rps > 0 else 0.0
        self._last: dict[str, float] = {}
        self._counts: dict[str, int] = {}
        self._lock = threading.Lock()
        self._clock = clock
        self._sleep = sleep

    def _key(self, target: str) -> str:
        t = (target or "").strip().lower()
        # Reduce URL/host:port to a bare host key so all requests to the same
        # target share one bucket.
        for pfx in ("http://", "https://"):
            if t.startswith(pfx):
                t = t[len(pfx):]
        t = t.split("/")[0].split("@")[-1].split(":")[0]
        return t or "unknown"

    def wait(self, target: str) -> float:
        """Block until this target may be hit again. Returns seconds waited."""
        if self._min_interval <= 0:
            with self._lock:
                self._counts[self._key(target)] = self._counts.get(self._key(target), 0) + 1
            return 0.0
        key = self._key(target)
        with self._lock:
            now = self._clock()
            last = self._last.get(key)
            if last is None:
                wait = 0.0
            else:
                elapsed = now - last
                wait = max(0.0, self._min_interval - elapsed)
            # Reserve this slot now so concurrent callers pace correctly.
            self._last[key] = now + wait
            self._counts[key] = self._counts.get(key, 0) + 1
        if wait > 0:
            self._sleep(wait)
        return wait

    def request_count(self, target: str) -> int:
        with self._lock:
            return self._counts.get(self._key(target), 0)

    def reset(self) -> None:
        with self._lock:
            self._last.clear()
            self._counts.clear()


_GLOBAL: TargetRateLimiter | None = None


def get_throttle() -> TargetRateLimiter:
    """Return the process-wide per-target throttle (configured via QUARR_TARGET_RPS)."""
    global _GLOBAL
    if _GLOBAL is None:
        try:
            rps = float(os.environ.get("QUARR_TARGET_RPS", "0") or "0")
        except ValueError:
            rps = 0.0
        _GLOBAL = TargetRateLimiter(rps=rps)
    return _GLOBAL


def set_target_rps(rps: float) -> None:
    """Reconfigure the global throttle's per-target rate (requests/second)."""
    global _GLOBAL
    _GLOBAL = TargetRateLimiter(rps=rps)
