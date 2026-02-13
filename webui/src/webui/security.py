# Copyright (c) 2026 John Earle
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
BlackChamber ICES WebUI — Security Utilities

Includes rate limiting and other security helpers.
"""

import time
from dataclasses import dataclass
from typing import Dict


@dataclass
class RateLimitEntry:
    count: int
    start_time: float


class RateLimiter:
    """
    A simple in-memory rate limiter using a fixed window algorithm.

    Args:
        limit: Number of allowed requests per window.
        window_seconds: Duration of the window in seconds.
    """
    def __init__(self, limit: int = 5, window_seconds: int = 60):
        self.limit = limit
        self.window_seconds = window_seconds
        self.entries: Dict[str, RateLimitEntry] = {}
        self._last_cleanup = time.time()

    def is_allowed(self, key: str) -> bool:
        now = time.time()

        # Periodic cleanup (every 60s) to prevent memory leak
        if now - self._last_cleanup > 60:
            self._cleanup(now)
            self._last_cleanup = now

        entry = self.entries.get(key)

        # New entry
        if not entry:
            self.entries[key] = RateLimitEntry(count=1, start_time=now)
            return True

        # Window expired for this entry?
        if now - entry.start_time > self.window_seconds:
            # Reset the window for this key
            entry.start_time = now
            entry.count = 1
            return True

        # Check limit
        if entry.count >= self.limit:
            return False

        # Increment
        entry.count += 1
        return True

    def _cleanup(self, now: float):
        """Remove expired entries."""
        expired_keys = [
            k for k, v in self.entries.items()
            if now - v.start_time > self.window_seconds
        ]
        for k in expired_keys:
            del self.entries[k]
