"""
BlackChamber ICES WebUI — Security Utilities

Includes rate limiting and other security-related helpers.
"""

import time
from collections import defaultdict
from threading import Lock

class RateLimiter:
    """A simple thread-safe in-memory rate limiter."""

    def __init__(self, requests_per_minute: int = 5):
        self.limit = requests_per_minute
        # Store timestamps of requests per IP: {ip: [ts1, ts2, ...]}
        self.requests = defaultdict(list)
        self.lock = Lock()
        self.last_cleanup = 0

    def check(self, ip: str) -> bool:
        """
        Check if the request from the given IP is allowed.
        Returns True if allowed, False if rate limit exceeded.
        """
        with self.lock:
            now = time.monotonic()

            # Periodic cleanup to prevent memory leaks
            # Run cleanup at most once per minute if we have many IPs
            if len(self.requests) > 1000 and now - self.last_cleanup > 60:
                self._cleanup(now)
                self.last_cleanup = now

            # Filter out timestamps older than 60 seconds for the current IP
            self.requests[ip] = [t for t in self.requests[ip] if now - t < 60]

            if len(self.requests[ip]) >= self.limit:
                return False

            self.requests[ip].append(now)
            return True

    def _cleanup(self, now: float):
        """Remove IPs that have no recent requests."""
        keys_to_delete = []
        # Create a list of items to avoid runtime error if dict changes size
        # (Though we hold the lock, so no other thread changes it, but Python
        #  disallows changing dict size during iteration)
        for ip, timestamps in list(self.requests.items()):
            # Keep only valid timestamps
            valid = [t for t in timestamps if now - t < 60]
            if not valid:
                keys_to_delete.append(ip)
            else:
                self.requests[ip] = valid

        for ip in keys_to_delete:
            del self.requests[ip]
