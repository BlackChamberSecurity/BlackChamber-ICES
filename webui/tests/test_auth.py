import os
import sys
from unittest.mock import MagicMock

# Mock jose module before importing webui.auth
sys.modules["jose"] = MagicMock()
sys.modules["jose.jwt"] = MagicMock()
sys.modules["jose.JWTError"] = Exception

# Ensure the module can be found
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

# Set required environment variables before import
os.environ["WEBUI_ADMIN_USER"] = "admin"
os.environ["WEBUI_ADMIN_PASSWORD"] = "changeme"

from webui.auth import authenticate, create_token

# Mock create_token to return a dummy token instead of failing due to missing jose
# We need to patch it in the module where it is defined
import webui.auth
webui.auth.create_token = lambda username: f"dummy_token_{username}"

def test_authenticate():
    # Test valid credentials (default)
    token = authenticate("admin", "changeme")
    assert token == "dummy_token_admin", f"Authentication failed with valid credentials, got {token}"

    # Test invalid username
    token = authenticate("wronguser", "changeme")
    assert token is None, "Authentication succeeded with invalid username"

    # Test invalid password
    token = authenticate("admin", "wrongpass")
    assert token is None, "Authentication succeeded with invalid password"

    print("All tests passed!")

if __name__ == "__main__":
    test_authenticate()
