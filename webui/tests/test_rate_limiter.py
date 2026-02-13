import unittest
import time
import sys
import os

# Ensure the module can be found
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from webui.security import RateLimiter, RateLimitEntry

class TestRateLimiter(unittest.TestCase):
    def test_basic_limit(self):
        limiter = RateLimiter(limit=2, window_seconds=1)

        # 1st request: Allowed
        self.assertTrue(limiter.is_allowed("ip1"))

        # 2nd request: Allowed
        self.assertTrue(limiter.is_allowed("ip1"))

        # 3rd request: Blocked
        self.assertFalse(limiter.is_allowed("ip1"))

    def test_window_reset(self):
        # Shorter window for test
        limiter = RateLimiter(limit=1, window_seconds=0.1)

        # 1st request: Allowed
        self.assertTrue(limiter.is_allowed("ip2"))

        # 2nd request: Blocked immediately
        self.assertFalse(limiter.is_allowed("ip2"))

        # Wait for window to expire
        time.sleep(0.2)

        # 3rd request (after reset): Allowed
        self.assertTrue(limiter.is_allowed("ip2"))

    def test_multiple_keys(self):
        limiter = RateLimiter(limit=1, window_seconds=60)

        self.assertTrue(limiter.is_allowed("user1"))
        self.assertFalse(limiter.is_allowed("user1"))

        # Should be allowed as it is a different key
        self.assertTrue(limiter.is_allowed("user2"))
        self.assertFalse(limiter.is_allowed("user2"))

    def test_cleanup(self):
        limiter = RateLimiter(limit=5, window_seconds=1)

        # Add entry via public API
        limiter.is_allowed("old_ip")

        # Manually age the entry to simulate expiration
        limiter.entries["old_ip"].start_time = time.time() - 2

        # Force cleanup on next check
        limiter._last_cleanup = 0

        # Trigger check for new IP
        limiter.is_allowed("new_ip")

        # "old_ip" should be gone
        self.assertNotIn("old_ip", limiter.entries)
        self.assertIn("new_ip", limiter.entries)

if __name__ == "__main__":
    unittest.main()
