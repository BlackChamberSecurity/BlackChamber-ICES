"""
BlackChamber ICES WebUI — Security Utilities

Provides helper classes for security, such as rate limiting.
"""

import time
from collections import defaultdict
from fastapi import HTTPException, Request

class RateLimiter:
    """Simple in-memory rate limiter per IP address with periodic cleanup."""

    def __init__(self, limit: int = 5, window_seconds: int = 60, cleanup_interval: int = 1000):
        self.limit = limit
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)
        self.cleanup_interval = cleanup_interval
        self._request_counter = 0

    async def __call__(self, request: Request):
        # Clean up global state periodically to prevent memory leaks from inactive IPs
        self._request_counter += 1
        if self._request_counter >= self.cleanup_interval:
            self._cleanup()
            self._request_counter = 0

        client_ip = request.client.host if request.client else "unknown"
        now = time.time()

        # Clean up old timestamps for this IP
        self.requests[client_ip] = [
            t for t in self.requests[client_ip]
            if now - t < self.window_seconds
        ]

        if len(self.requests[client_ip]) >= self.limit:
            raise HTTPException(
                status_code=429,
                detail="Too many login attempts. Please try again later."
            )

        self.requests[client_ip].append(now)

    def _cleanup(self):
        """Remove IPs that have no recent requests."""
        now = time.time()
        keys_to_delete = []

        # Iterate over a copy of items to be safe
        for ip, timestamps in list(self.requests.items()):
            # Filter timestamps
            valid = [t for t in timestamps if now - t < self.window_seconds]
            if not valid:
                keys_to_delete.append(ip)
            else:
                self.requests[ip] = valid

        for key in keys_to_delete:
            del self.requests[key]
