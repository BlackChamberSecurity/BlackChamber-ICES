import os
import sys
import subprocess
import unittest

class TestAuthConfig(unittest.TestCase):
    def test_missing_env_vars_raises_error(self):
        """Verify that importing webui.auth raises ValueError if env vars are missing."""
        # We need to run this in a separate process to ensure a clean environment
        # and to capture the import error.

        # We also need to mock 'jose' in the subprocess, which is tricky.
        # Instead of mocking in the subprocess, we can use a script that does the mocking.

        script = """
import sys
import os
from unittest.mock import MagicMock

# Mock jose
sys.modules["jose"] = MagicMock()
sys.modules["jose.jwt"] = MagicMock()
sys.modules["jose.JWTError"] = Exception

# Add src to path
sys.path.insert(0, os.path.abspath("webui/src"))

try:
    import webui.auth
except ValueError as e:
    print("Caught expected ValueError")
    sys.exit(0)
except Exception as e:
    print(f"Caught unexpected exception: {type(e).__name__}: {e}")
    sys.exit(1)

print("Import succeeded unexpectedly")
sys.exit(1)
"""

        # Run the script with empty environment (except for PATH/PYTHONPATH if needed)
        env = os.environ.copy()
        env.pop("WEBUI_ADMIN_USER", None)
        env.pop("WEBUI_ADMIN_PASSWORD", None)

        result = subprocess.run(
            [sys.executable, "-c", script],
            env=env,
            capture_output=True,
            text=True
        )

        self.assertEqual(result.returncode, 0, f"Script failed: {result.stdout} {result.stderr}")
        self.assertIn("Caught expected ValueError", result.stdout)

if __name__ == "__main__":
    unittest.main()
