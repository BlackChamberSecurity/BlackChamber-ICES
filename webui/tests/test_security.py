import sys
import os
import time
import asyncio
from unittest.mock import MagicMock

# Mock fastapi if not available
try:
    import fastapi
except ImportError:
    # Create a mock module for fastapi
    mock_fastapi = MagicMock()

    # Define the exceptions/classes we need
    class HTTPException(Exception):
        def __init__(self, status_code, detail):
            self.status_code = status_code
            self.detail = detail

    class Request:
        pass

    mock_fastapi.HTTPException = HTTPException
    mock_fastapi.Request = Request

    # Inject into sys.modules
    sys.modules["fastapi"] = mock_fastapi

# Ensure the module can be found
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from webui.security import RateLimiter, HTTPException as RateLimitEx

def test_rate_limiter():
    print("Starting RateLimiter tests...")
    limiter = RateLimiter(limit=2, window_seconds=1)

    # Mock request object
    request = MagicMock()
    request.client.host = "127.0.0.1"

    async def run_test():
        # First request - should pass
        try:
            await limiter(request)
            print("Request 1: Passed")
        except RateLimitEx:
            print("Request 1: Failed (Unexpected)")
            sys.exit(1)

        # Second request - should pass
        try:
            await limiter(request)
            print("Request 2: Passed")
        except RateLimitEx:
            print("Request 2: Failed (Unexpected)")
            sys.exit(1)

        # Third request - should fail (limit is 2)
        try:
            await limiter(request)
            print("Request 3: Passed (Unexpected)")
            sys.exit(1)
        except RateLimitEx as e:
            if e.status_code == 429:
                print("Request 3: Failed (Expected 429)")
            else:
                print(f"Request 3: Failed with wrong status code {e.status_code}")
                sys.exit(1)

        # Wait for window to expire
        time.sleep(1.1)

        # Fourth request - should pass (window reset)
        try:
            await limiter(request)
            print("Request 4: Passed")
        except RateLimitEx:
            print("Request 4: Failed (Unexpected)")
            sys.exit(1)

    asyncio.run(run_test())
    print("All tests passed!")

if __name__ == "__main__":
    test_rate_limiter()
