import unittest
import sys
import os
import importlib
from unittest.mock import MagicMock, patch

# Ensure module path is correct
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

class TestRateLimiter(unittest.TestCase):
    def setUp(self):
        # Create mocks
        self.mock_fastapi = MagicMock()

        # Mock HTTPException
        class MockHTTPException(Exception):
            def __init__(self, status_code, detail=None):
                self.status_code = status_code
                self.detail = detail

        self.mock_fastapi.HTTPException = MockHTTPException

        # Mock Request
        class MockRequest:
            def __init__(self, client_ip):
                self.client = MagicMock()
                self.client.host = client_ip

        self.mock_fastapi.Request = MockRequest
        self.MockRequest = MockRequest
        self.MockHTTPException = MockHTTPException

        # Patch sys.modules dictionary to mock fastapi
        self.modules_patcher = patch.dict(sys.modules, {"fastapi": self.mock_fastapi})
        self.modules_patcher.start()

        # Import the module under test (re-import to pick up mocks)
        import webui.security
        importlib.reload(webui.security)
        self.security_module = webui.security
        self.RateLimiter = self.security_module.RateLimiter

        self.limiter = self.RateLimiter(requests_per_minute=2, max_clients=10)

    def tearDown(self):
        self.modules_patcher.stop()

    def test_allowed_requests(self):
        req = self.MockRequest("127.0.0.1")
        self.limiter.check(req)
        self.limiter.check(req)

    def test_blocked_requests(self):
        req = self.MockRequest("127.0.0.2")
        self.limiter.check(req)
        self.limiter.check(req)

        with self.assertRaises(self.MockHTTPException) as cm:
            self.limiter.check(req)
        self.assertEqual(cm.exception.status_code, 429)

    def test_window_expiration(self):
        req = self.MockRequest("127.0.0.3")

        with patch("time.monotonic") as mock_time:
            mock_time.return_value = 100.0
            self.limiter.check(req)
            self.limiter.check(req)

            with self.assertRaises(self.MockHTTPException):
                self.limiter.check(req)

            mock_time.return_value = 161.0
            try:
                self.limiter.check(req)
            except self.MockHTTPException:
                self.fail("Request should be allowed after window expiration")

    def test_max_clients_cleanup(self):
        limiter = self.RateLimiter(requests_per_minute=5, max_clients=2)

        req1 = self.MockRequest("1.1.1.1")
        req2 = self.MockRequest("2.2.2.2")
        req3 = self.MockRequest("3.3.3.3")

        limiter.check(req1)
        limiter.check(req2)

        # Should have 2 clients
        self.assertEqual(len(limiter.requests), 2)

        # Adding 3rd client triggers cleanup (clear all)
        limiter.check(req3)

        # After clear, only req3 is present (req1 and req2 cleared)
        # Wait, if I clear all, then add req3, size is 1.
        self.assertEqual(len(limiter.requests), 1)
        self.assertIn("3.3.3.3", limiter.requests)
        self.assertNotIn("1.1.1.1", limiter.requests)

if __name__ == "__main__":
    unittest.main()
