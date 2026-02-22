import os
import sys
import unittest
import subprocess

class TestAuthConfig(unittest.TestCase):
    def test_missing_env_vars(self):
        """Verify that webui.auth fails to import if environment variables are missing."""
        # Create a small script to attempt import
        script = """
import os
import sys
from unittest.mock import MagicMock

# Mock jose module
sys.modules["jose"] = MagicMock()
sys.modules["jose.jwt"] = MagicMock()
sys.modules["jose.JWTError"] = Exception

# Add src to path
# We need absolute path to src relative to where this test is run (repo root)
sys.path.insert(0, os.path.abspath("webui/src"))

try:
    import webui.auth
except ValueError as e:
    print(str(e))
    sys.exit(0)
except Exception as e:
    print(f"Unexpected error: {e}")
    sys.exit(1)

print("Import succeeded unexpectedly")
sys.exit(1)
"""
        # Run the script in a subprocess with a clean environment
        env = os.environ.copy()
        if "WEBUI_ADMIN_USER" in env:
            del env["WEBUI_ADMIN_USER"]
        if "WEBUI_ADMIN_PASSWORD" in env:
            del env["WEBUI_ADMIN_PASSWORD"]

        # Run from repo root
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            env=env,
            cwd=os.getcwd()
        )

        self.assertEqual(result.returncode, 0, f"Script failed with output:\n{result.stderr}\n{result.stdout}")
        self.assertIn("WEBUI_ADMIN_USER and WEBUI_ADMIN_PASSWORD environment variables must be set.", result.stdout)

if __name__ == "__main__":
    unittest.main()
