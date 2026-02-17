import time
import threading
from collections import defaultdict
from fastapi import HTTPException, Request

class RateLimiter:
    """Simple in-memory rate limiter using a fixed window."""

    def __init__(self, requests_per_minute: int = 5, max_clients: int = 1000):
        self.requests_per_minute = requests_per_minute
        self.window_size = 60  # seconds
        self.max_clients = max_clients
        self.requests = defaultdict(list)
        self.lock = threading.Lock()

    def check(self, request: Request):
        """Check if the request is allowed based on client IP.

        Note: Uses request.client.host which may be a proxy IP.
        For production behind proxies, consider X-Forwarded-For validation.
        """
        client_ip = request.client.host if request.client else "unknown"
        now = time.monotonic()

        with self.lock:
            # Prevent memory exhaustion by clearing old entries if too many clients
            # Only clear if we are about to add a NEW client and we are at capacity
            if client_ip not in self.requests and len(self.requests) >= self.max_clients:
                # Simple strategy: clear all to prevent OOM.
                self.requests.clear()

            # Clean up old requests for this client
            if client_ip in self.requests:
                self.requests[client_ip] = [
                    req_time for req_time in self.requests[client_ip]
                    if now - req_time < self.window_size
                ]
                # If list is empty after cleanup, remove the key to save space
                if not self.requests[client_ip]:
                    del self.requests[client_ip]

            # Check limit (defaultdict creates empty list if key missing)
            # But wait, I just deleted it if empty.
            # So I need to re-check or just handle it.

            current_requests = self.requests[client_ip] # Creates new list if deleted

            if len(current_requests) >= self.requests_per_minute:
                raise HTTPException(status_code=429, detail="Too many login attempts. Please try again later.")

            # Record request
            self.requests[client_ip].append(now)
