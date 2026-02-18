import unittest
import time
from unittest.mock import patch
import sys
import os

# Ensure the module can be found
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from webui.security import RateLimiter

class TestRateLimiter(unittest.TestCase):
    def test_limit_enforced(self):
        limiter = RateLimiter(requests_per_minute=2)
        ip = "127.0.0.1"

        self.assertTrue(limiter.check(ip))
        self.assertTrue(limiter.check(ip))
        self.assertFalse(limiter.check(ip))

    def test_window_expiration(self):
        limiter = RateLimiter(requests_per_minute=2)
        ip = "127.0.0.1"

        with patch("webui.security.time.monotonic") as mock_time:
            # T0
            mock_time.return_value = 100.0
            self.assertTrue(limiter.check(ip))

            # T0 + 10s
            mock_time.return_value = 110.0
            self.assertTrue(limiter.check(ip))

            # Limit reached
            self.assertFalse(limiter.check(ip))

            # T0 + 61s (first request expired)
            mock_time.return_value = 162.0
            self.assertTrue(limiter.check(ip))

if __name__ == "__main__":
    unittest.main()
