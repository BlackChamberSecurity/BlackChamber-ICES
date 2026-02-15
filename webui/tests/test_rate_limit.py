import time
import unittest
import os
import sys
from unittest.mock import MagicMock

# Mock fastapi before importing webui.security
class MockHTTPException(Exception):
    def __init__(self, status_code, detail=None):
        self.status_code = status_code
        self.detail = detail

sys.modules["fastapi"] = MagicMock()
sys.modules["fastapi"].HTTPException = MockHTTPException
sys.modules["fastapi"].Request = MagicMock()

# Ensure the module can be found
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from webui.security import RateLimiter
from fastapi import HTTPException, Request

class TestRateLimiter(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.limiter = RateLimiter(max_attempts=3, window_seconds=1, cleanup_interval=1)
        self.request = MagicMock()
        self.request.client.host = "127.0.0.1"
        self.request.headers = {}

    async def test_check_under_limit(self):
        # 3 attempts allowed
        await self.limiter.check(self.request)
        await self.limiter.check(self.request)
        await self.limiter.check(self.request)

    async def test_check_over_limit(self):
        # 3 attempts allowed
        await self.limiter.check(self.request)
        await self.limiter.check(self.request)
        await self.limiter.check(self.request)

        # 4th attempt should fail
        with self.assertRaises(HTTPException) as cm:
            await self.limiter.check(self.request)
        self.assertEqual(cm.exception.status_code, 429)

    async def test_window_reset(self):
        await self.limiter.check(self.request)
        await self.limiter.check(self.request)
        await self.limiter.check(self.request)

        # Wait for window to expire
        time.sleep(1.1)

        # Should be allowed again
        await self.limiter.check(self.request)

    async def test_cleanup(self):
        await self.limiter.check(self.request)

        # Wait for cleanup interval
        time.sleep(1.1)

        # Trigger check (which triggers cleanup)
        await self.limiter.check(self.request)

    async def test_different_ips(self):
        req1 = MagicMock()
        req1.client.host = "1.1.1.1"
        req1.headers = {}

        req2 = MagicMock()
        req2.client.host = "2.2.2.2"
        req2.headers = {}

        # IP 1 uses all attempts
        await self.limiter.check(req1)
        await self.limiter.check(req1)
        await self.limiter.check(req1)
        with self.assertRaises(HTTPException):
            await self.limiter.check(req1)

        # IP 2 should still be allowed
        await self.limiter.check(req2)
        await self.limiter.check(req2)

    async def test_forwarded_for(self):
        req = MagicMock()
        req.headers = {"X-Forwarded-For": "10.0.0.1, 10.0.0.2"}
        req.client.host = "127.0.0.1"

        await self.limiter.check(req)
        await self.limiter.check(req)
        await self.limiter.check(req)

        with self.assertRaises(HTTPException):
            await self.limiter.check(req)

        # Check that it used the forwarded IP, not the client host
        self.assertIn("10.0.0.1", self.limiter._attempts)

if __name__ == "__main__":
    unittest.main()
