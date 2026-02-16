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

Provides rate limiting and other security helpers.
"""

import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class RateLimitEntry:
    count: int = 0
    start_time: float = field(default_factory=time.monotonic)


class RateLimiter:
    """
    In-memory rate limiter using a fixed window counter.

    Args:
        requests (int): Max requests allowed per window.
        window (int): Window size in seconds.
    """

    def __init__(self, requests: int = 5, window: int = 60):
        self.requests = requests
        self.window = window
        self.entries: defaultdict[str, RateLimitEntry] = defaultdict(RateLimitEntry)
        self.lock = threading.Lock()
        self._check_count = 0  # For periodic cleanup triggering

    def check(self, key: str) -> bool:
        """
        Check if a request is allowed for the given key.
        Returns True if allowed, False if limit exceeded.
        """
        with self.lock:
            now = time.monotonic()
            entry = self.entries[key]

            # Reset if window expired
            if now - entry.start_time > self.window:
                entry.start_time = now
                entry.count = 0

            # Check limit
            if entry.count >= self.requests:
                return False

            # Increment and allow
            entry.count += 1

            # Periodic cleanup trigger
            self._check_count += 1
            if self._check_count >= 1000:
                self._cleanup(now)
                self._check_count = 0

            return True

    def _cleanup(self, now: float):
        """Remove expired entries to prevent memory leaks."""
        expired = [
            k for k, v in self.entries.items()
            if now - v.start_time > self.window
        ]
        for k in expired:
            del self.entries[k]
