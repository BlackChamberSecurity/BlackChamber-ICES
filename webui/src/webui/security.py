import time
from fastapi import HTTPException, Request

class RateLimiter:
    """Simple in-memory rate limiter using a sliding window of timestamps."""

    def __init__(self, max_attempts: int = 5, window_seconds: int = 60, cleanup_interval: int = 600):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.cleanup_interval = cleanup_interval
        self._attempts: dict[str, list[float]] = {}
        self._last_cleanup = time.monotonic()

    async def check(self, request: Request):
        """Check if the request exceeds the rate limit."""
        # Check for X-Forwarded-For header first (standard for proxies)
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            ip = forwarded.split(",")[0].strip()
        else:
            ip = request.client.host if request.client else "unknown"

        now = time.monotonic()

        # Periodic cleanup of expired entries
        if now - self._last_cleanup > self.cleanup_interval:
            self._cleanup(now)

        # Filter attempts for this IP within the window
        attempts = self._attempts.get(ip, [])
        # Keep only timestamps within the window
        valid_attempts = [t for t in attempts if now - t < self.window_seconds]

        if len(valid_attempts) >= self.max_attempts:
            raise HTTPException(status_code=429, detail="Too many login attempts. Please try again later.")

        valid_attempts.append(now)
        self._attempts[ip] = valid_attempts

    def _cleanup(self, now: float):
        """Remove entries that have no valid attempts within the window."""
        keys_to_delete = []
        for ip, timestamps in self._attempts.items():
            # Keep only timestamps within the window
            valid_timestamps = [t for t in timestamps if now - t < self.window_seconds]
            if not valid_timestamps:
                keys_to_delete.append(ip)
            else:
                self._attempts[ip] = valid_timestamps

        for key in keys_to_delete:
            del self._attempts[key]

        self._last_cleanup = now
