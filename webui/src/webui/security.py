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

This module provides security-related utilities such as rate limiting.
"""

import time
from dataclasses import dataclass

@dataclass
class RateLimitEntry:
    count: int
    start_time: float

class RateLimiter:
    """
    A simple in-memory rate limiter using a fixed window algorithm.
    It tracks the number of requests per key (e.g., IP address) within a time window.
    """

    def __init__(self, requests_per_minute: int = 5, cleanup_interval: int = 600):
        self.requests_per_minute = requests_per_minute
        self.cleanup_interval = cleanup_interval
        self.entries: dict[str, RateLimitEntry] = {}
        self.last_cleanup = time.time()

    def check(self, key: str) -> bool:
        """
        Check if a request from the given key is allowed.
        Returns True if allowed, False otherwise.
        """
        now = time.time()
        self._cleanup(now)

        entry = self.entries.get(key)
        if not entry:
            self.entries[key] = RateLimitEntry(count=1, start_time=now)
            return True

        if now - entry.start_time > 60:
            # Reset window
            entry.start_time = now
            entry.count = 1
            return True

        if entry.count >= self.requests_per_minute:
            return False

        entry.count += 1
        return True

    def _cleanup(self, now: float):
        """
        Clean up old entries to prevent memory leaks.
        """
        if now - self.last_cleanup < self.cleanup_interval:
            return

        # remove entries older than 60 seconds
        keys_to_remove = [k for k, v in self.entries.items() if now - v.start_time > 60]
        for k in keys_to_remove:
            del self.entries[k]

        self.last_cleanup = now
