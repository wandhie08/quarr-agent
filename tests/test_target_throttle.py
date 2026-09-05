"""Tests for per-target request throttling (scope compliance)."""

import pytest

from quarr.core.target_throttle import TargetRateLimiter, get_throttle, set_target_rps


class _FakeClock:
    def __init__(self):
        self.t = 0.0
        self.slept = 0.0

    def now(self):
        return self.t

    def sleep(self, s):
        self.slept += s
        self.t += s  # advancing time as if we waited


@pytest.mark.unit
class TestTargetRateLimiter:
    def test_no_limit_is_noop(self):
        clk = _FakeClock()
        rl = TargetRateLimiter(rps=0, clock=clk.now, sleep=clk.sleep)
        for _ in range(5):
            assert rl.wait("target.com") == 0.0
        assert clk.slept == 0.0
        assert rl.request_count("target.com") == 5

    def test_first_request_no_wait(self):
        clk = _FakeClock()
        rl = TargetRateLimiter(rps=2, clock=clk.now, sleep=clk.sleep)  # 0.5s interval
        assert rl.wait("http://target.com/a") == 0.0

    def test_second_request_waits_min_interval(self):
        clk = _FakeClock()
        rl = TargetRateLimiter(rps=2, clock=clk.now, sleep=clk.sleep)  # 0.5s
        rl.wait("target.com")
        w = rl.wait("target.com")
        assert abs(w - 0.5) < 1e-6  # had to wait the full interval

    def test_per_target_isolation(self):
        clk = _FakeClock()
        rl = TargetRateLimiter(rps=1, clock=clk.now, sleep=clk.sleep)  # 1s
        rl.wait("a.com")
        # A different target should not be throttled by a.com's timer.
        assert rl.wait("b.com") == 0.0

    def test_host_key_normalizes_url_forms(self):
        clk = _FakeClock()
        rl = TargetRateLimiter(rps=1, clock=clk.now, sleep=clk.sleep)
        rl.wait("https://target.com/path?x=1")
        # Same host via different URL form shares the bucket → must wait.
        assert rl.wait("http://target.com/other") > 0

    def test_reset(self):
        rl = TargetRateLimiter(rps=5)
        rl.wait("x.com")
        rl.reset()
        assert rl.request_count("x.com") == 0

    def test_global_throttle_configurable(self):
        set_target_rps(0)  # reset to no-op for other tests
        assert isinstance(get_throttle(), TargetRateLimiter)
        assert get_throttle().rps == 0
