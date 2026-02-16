import os
import sys
import unittest
from unittest.mock import MagicMock
import time

# Ensure the module can be found
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from webui.security import RateLimiter

class TestRateLimiter(unittest.TestCase):
    def test_basic_limit(self):
        limiter = RateLimiter(requests=3, window=10)

        # First 3 requests allowed
        self.assertTrue(limiter.check("ip1"))
        self.assertTrue(limiter.check("ip1"))
        self.assertTrue(limiter.check("ip1"))

        # 4th request blocked
        self.assertFalse(limiter.check("ip1"))

        # Different IP allowed
        self.assertTrue(limiter.check("ip2"))

    def test_window_reset(self):
        limiter = RateLimiter(requests=1, window=0.1)

        self.assertTrue(limiter.check("ip1"))
        self.assertFalse(limiter.check("ip1"))

        time.sleep(0.15)

        # Allowed again after window expires
        self.assertTrue(limiter.check("ip1"))

    def test_cleanup(self):
        limiter = RateLimiter(requests=10, window=0.1)

        # Create expired entries
        limiter.check("ip1")
        limiter.check("ip2")
        time.sleep(0.2)

        # Trigger cleanup explicitly
        limiter._cleanup(time.monotonic())

        self.assertFalse(limiter.entries, "Expired entries should be cleaned up")

    def test_check_with_threading_lock(self):
        # This test ensures no exceptions are raised during rapid access
        # but doesn't strictly verify concurrency correctness
        limiter = RateLimiter(requests=1000, window=10)

        threads = []
        import threading

        def worker():
            for _ in range(100):
                limiter.check("ip1")

        for _ in range(10):
            t = threading.Thread(target=worker)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        self.assertEqual(limiter.entries["ip1"].count, 1000)

if __name__ == "__main__":
    unittest.main()
