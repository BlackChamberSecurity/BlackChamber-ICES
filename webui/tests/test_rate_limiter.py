# Copyright (c) 2026 John Earle
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import time
import unittest
from unittest.mock import patch
from webui.security import RateLimiter, RateLimitEntry

class TestRateLimiter(unittest.TestCase):

    def test_allow_initial_requests(self):
        limiter = RateLimiter(requests_per_minute=2)
        self.assertTrue(limiter.check("ip1"))
        self.assertTrue(limiter.check("ip1"))

    def test_block_excessive_requests(self):
        limiter = RateLimiter(requests_per_minute=2)
        limiter.check("ip1")
        limiter.check("ip1")
        self.assertFalse(limiter.check("ip1"))

    def test_reset_window(self):
        limiter = RateLimiter(requests_per_minute=1)
        limiter.check("ip1")
        self.assertFalse(limiter.check("ip1"))

        # Simulate time passing (mock time.time or just modify entry)
        limiter.entries["ip1"].start_time = time.time() - 61
        self.assertTrue(limiter.check("ip1"))

    def test_cleanup(self):
        limiter = RateLimiter(requests_per_minute=1, cleanup_interval=0)
        limiter.check("ip1")

        # Simulate old entry
        limiter.entries["ip1"].start_time = time.time() - 61

        # This call should trigger cleanup because cleanup_interval is 0
        limiter.check("ip2")

        # ip1 should be removed
        self.assertNotIn("ip1", limiter.entries)

if __name__ == "__main__":
    unittest.main()
