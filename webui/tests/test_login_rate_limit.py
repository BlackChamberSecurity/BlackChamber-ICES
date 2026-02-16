import sys
import os
import asyncio
import unittest
from unittest.mock import MagicMock

# ---------------------------------------------------------------------------
# Mocks setup
# ---------------------------------------------------------------------------

# Mock fastapi
mock_fastapi = MagicMock()
sys.modules["fastapi"] = mock_fastapi
sys.modules["fastapi.middleware.cors"] = MagicMock()
sys.modules["fastapi.responses"] = MagicMock()
sys.modules["fastapi.staticfiles"] = MagicMock()

# Setup pass-through decorator for app.post/get
def pass_through_decorator(*args, **kwargs):
    def decorator(func):
        return func
    return decorator

# Setup mock app instance
mock_app = MagicMock()
mock_app.post.side_effect = pass_through_decorator
mock_app.get.side_effect = pass_through_decorator
mock_app.add_middleware = MagicMock()
mock_app.mount = MagicMock()

# Configure FastAPI constructor to return mock_app
mock_fastapi.FastAPI.return_value = mock_app

# Define HTTPException to allow catching it
class MockHTTPException(Exception):
    def __init__(self, status_code, detail=None):
        self.status_code = status_code
        self.detail = detail

mock_fastapi.HTTPException = MockHTTPException
mock_fastapi.Request = MagicMock
mock_fastapi.Depends = MagicMock()

# Mock pydantic
mock_pydantic = MagicMock()
sys.modules["pydantic"] = mock_pydantic
class MockBaseModel:
    pass
mock_pydantic.BaseModel = MockBaseModel

# Mock jose
sys.modules["jose"] = MagicMock()

# Mock webui.queries to avoid database connection
sys.modules["webui.queries"] = MagicMock()

# Ensure we can import from src
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

# ---------------------------------------------------------------------------
# Import SUT
# ---------------------------------------------------------------------------

# Now import main
from webui import main

class TestLoginRateLimit(unittest.TestCase):
    def setUp(self):
        # Reset the rate limiter before each test
        main.login_limiter.entries.clear()

        # Mock authenticate to succeed by default
        self.original_authenticate = main.authenticate
        main.authenticate = MagicMock(return_value="fake-token")

    def tearDown(self):
        main.authenticate = self.original_authenticate

    def test_rate_limit_enforcement(self):
        # Mock Request object
        request = MagicMock()
        request.client.host = "192.168.1.100"

        # Mock LoginRequest body
        body = MagicMock()
        body.username = "admin"
        body.password = "password"

        # Helper to run the async login function
        def run_login():
            return asyncio.run(main.login(request, body))

        # First 5 requests should succeed
        for i in range(5):
            try:
                response = run_login()
                self.assertEqual(response["token"], "fake-token")
            except MockHTTPException as e:
                self.fail(f"Request {i+1} failed unexpectedly with {e.status_code}")

        # 6th request should fail with 429
        with self.assertRaises(MockHTTPException) as cm:
            run_login()

        self.assertEqual(cm.exception.status_code, 429)
        self.assertEqual(cm.exception.detail, "Too Many Requests")

    def test_rate_limit_different_ips(self):
        # IP 1
        req1 = MagicMock()
        req1.client.host = "10.0.0.1"

        # IP 2
        req2 = MagicMock()
        req2.client.host = "10.0.0.2"

        body = MagicMock()

        def run_login(req):
            return asyncio.run(main.login(req, body))

        # Exhaust IP 1
        for _ in range(5):
            run_login(req1)

        # IP 1 blocked
        with self.assertRaises(MockHTTPException):
            run_login(req1)

        # IP 2 still allowed
        try:
            run_login(req2)
        except MockHTTPException:
            self.fail("IP 2 should not be blocked by IP 1's activity")

if __name__ == "__main__":
    unittest.main()
