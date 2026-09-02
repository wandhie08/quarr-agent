"""Unit tests for the token-bucket rate limiter (Phase 1, Req 11)."""

import pytest

from quarr.core.rate_limiter import TokenBucket
from quarr.core.exceptions import LLMRateLimitError


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


@pytest.mark.unit
async def test_burst_allowed_immediately():
    clock = FakeClock()
    slept = []

    async def fake_sleep(s):
        slept.append(s)

    bucket = TokenBucket(rate_per_minute=60, burst=5, clock=clock, sleep=fake_sleep)
    for _ in range(5):
        await bucket.acquire()
    assert slept == []  # burst consumed without waiting


@pytest.mark.unit
async def test_over_limit_waits_then_proceeds():
    clock = FakeClock()
    slept = []

    async def fake_sleep(s):
        slept.append(s)
        clock.advance(s)  # simulate time passing while asleep

    # 60/min = 1 token/sec, burst 1.
    bucket = TokenBucket(rate_per_minute=60, burst=1, clock=clock, sleep=fake_sleep)
    await bucket.acquire()          # consumes the single token
    await bucket.acquire()          # must wait ~1s for refill
    assert len(slept) == 1
    assert slept[0] == pytest.approx(1.0, abs=0.01)


@pytest.mark.unit
async def test_wait_exceeding_max_raises():
    clock = FakeClock()

    async def fake_sleep(s):
        clock.advance(s)

    # 6/min = 0.1 token/sec, burst 1 → refill of 1 token takes 10s.
    bucket = TokenBucket(rate_per_minute=6, burst=1, clock=clock, sleep=fake_sleep)
    await bucket.acquire()
    with pytest.raises(LLMRateLimitError) as ei:
        await bucket.acquire(max_wait=2.0)
    assert ei.value.context["max_wait"] == 2.0


@pytest.mark.unit
async def test_refill_over_time():
    clock = FakeClock()

    async def fake_sleep(s):
        clock.advance(s)

    bucket = TokenBucket(rate_per_minute=60, burst=2, clock=clock, sleep=fake_sleep)
    await bucket.acquire()
    await bucket.acquire()          # bucket now empty
    clock.advance(2.0)              # 2 seconds → 2 tokens refilled (capped at burst)
    await bucket.acquire()          # should not wait
    await bucket.acquire()          # should not wait
