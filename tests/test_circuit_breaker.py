"""Unit tests for the circuit breaker (Phase 1, Req 12)."""

import pytest

from quarr.core.circuit_breaker import CircuitBreaker, CircuitState
from quarr.core.exceptions import LLMConnectionError


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


async def _ok():
    return "ok"


async def _fail():
    raise LLMConnectionError("boom")


@pytest.mark.unit
async def test_opens_at_threshold():
    clock = FakeClock()
    cb = CircuitBreaker(threshold=3, window=60, reset_timeout=30, clock=clock)
    for _ in range(3):
        with pytest.raises(LLMConnectionError):
            await cb.call(_fail)
    assert cb.state == CircuitState.OPEN


@pytest.mark.unit
async def test_rejects_while_open():
    clock = FakeClock()
    cb = CircuitBreaker(threshold=1, window=60, reset_timeout=30, clock=clock)
    with pytest.raises(LLMConnectionError):
        await cb.call(_fail)
    assert cb.state == CircuitState.OPEN
    # Rejected fast without calling the function.
    called = {"n": 0}

    async def _spy():
        called["n"] += 1
        return "ok"

    with pytest.raises(LLMConnectionError):
        await cb.call(_spy)
    assert called["n"] == 0


@pytest.mark.unit
async def test_half_open_after_timeout_then_close_on_success():
    clock = FakeClock()
    cb = CircuitBreaker(threshold=1, window=60, reset_timeout=30, clock=clock)
    with pytest.raises(LLMConnectionError):
        await cb.call(_fail)
    assert cb.state == CircuitState.OPEN
    clock.advance(30)  # reset timeout elapsed
    result = await cb.call(_ok)  # probe succeeds
    assert result == "ok"
    assert cb.state == CircuitState.CLOSED


@pytest.mark.unit
async def test_half_open_probe_failure_reopens():
    clock = FakeClock()
    cb = CircuitBreaker(threshold=1, window=60, reset_timeout=30, clock=clock)
    with pytest.raises(LLMConnectionError):
        await cb.call(_fail)
    clock.advance(30)
    with pytest.raises(LLMConnectionError):
        await cb.call(_fail)  # probe fails
    assert cb.state == CircuitState.OPEN


@pytest.mark.unit
async def test_stays_closed_below_threshold():
    clock = FakeClock()
    cb = CircuitBreaker(threshold=3, window=60, reset_timeout=30, clock=clock)
    for _ in range(2):
        with pytest.raises(LLMConnectionError):
            await cb.call(_fail)
    assert cb.state == CircuitState.CLOSED
    # A success clears the failure count.
    assert await cb.call(_ok) == "ok"
    assert cb.state == CircuitState.CLOSED
