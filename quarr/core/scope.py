"""
scope.py - Scope limitations (Phase 4).

Enforces engagement scope (via normalized targets), a maximum number of distinct
targets, and a maximum tool-execution rate per engagement.
"""

import time
from collections import deque

from quarr.core.exceptions import PolicyViolationError
from quarr.core.validators import target as target_validator


class ScopeLimiter:
    def __init__(self, max_targets: int = 256, max_rate_per_min: int = 120, clock=None):
        self.max_targets = max_targets
        self.max_rate_per_min = max_rate_per_min
        self._clock = clock or time.monotonic
        self._seen_targets: set = set()
        self._exec_times: deque = deque()

    def check(self, target, engagement, session=None) -> None:
        # Rate limit (per engagement/session).
        now = self._clock()
        while self._exec_times and (now - self._exec_times[0]) > 60.0:
            self._exec_times.popleft()
        if len(self._exec_times) >= self.max_rate_per_min:
            raise PolicyViolationError(
                "Engagement execution rate limit exceeded",
                context={"limit": self.max_rate_per_min, "window_s": 60},
            )
        self._exec_times.append(now)

        if target:
            norm = target_validator.normalize(target)
            # Distinct-target cap.
            if norm not in self._seen_targets and len(self._seen_targets) >= self.max_targets:
                raise PolicyViolationError(
                    "Maximum distinct targets exceeded",
                    context={"limit": self.max_targets},
                )
            self._seen_targets.add(norm)
