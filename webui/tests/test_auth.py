import os
import sys
from unittest.mock import MagicMock, patch

# Mock jose module before importing webui.auth
sys.modules["jose"] = MagicMock()
sys.modules["jose.jwt"] = MagicMock()
sys.modules["jose.JWTError"] = Exception

# Ensure the module can be found
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from webui.auth import authenticate, create_token

# Mock create_token to return a dummy token instead of failing due to missing jose
# We need to patch it in the module where it is defined
import webui.auth
import unittest

webui.auth.create_token = lambda username: f"dummy_token_{username}"

class TestAuth(unittest.TestCase):
    def test_authenticate(self):
        # Test secure default: authentication should fail if env vars are missing
        # We simulate missing env vars by patching the module variables
        with patch("webui.auth.ADMIN_USER", None), patch("webui.auth.ADMIN_PASSWORD", None):
            token = authenticate("admin", "changeme")
            self.assertIsNone(token, "Authentication succeeded despite missing configuration")

        # Test with configured credentials
        with patch("webui.auth.ADMIN_USER", "admin"), patch("webui.auth.ADMIN_PASSWORD", "changeme"):
            # Test valid credentials
            token = authenticate("admin", "changeme")
            self.assertEqual(token, "dummy_token_admin", f"Authentication failed with valid credentials, got {token}")

            # Test invalid username
            token = authenticate("wronguser", "changeme")
            self.assertIsNone(token, "Authentication succeeded with invalid username")

            # Test invalid password
            token = authenticate("admin", "wrongpass")
            self.assertIsNone(token, "Authentication succeeded with invalid password")

if __name__ == "__main__":
    unittest.main()
