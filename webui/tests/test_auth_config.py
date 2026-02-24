import subprocess
import sys
import os

def test_missing_env_vars():
    # Code to run in subprocess
    # We mock 'jose' and attempt to import 'webui.auth' without setting env vars.
    code = """
import sys
import os
from unittest.mock import MagicMock

# Mock jose
sys.modules["jose"] = MagicMock()
sys.modules["jose.jwt"] = MagicMock()
sys.modules["jose.JWTError"] = Exception

# Add src to path. Assuming we run from repo root.
sys.path.insert(0, os.path.abspath("webui/src"))

try:
    import webui.auth
except ValueError as e:
    if "WEBUI_ADMIN_USER and WEBUI_ADMIN_PASSWORD must be set" in str(e):
        print("Caught expected ValueError")
        sys.exit(0)
    else:
        print(f"Caught ValueError but message was different: {e}")
        sys.exit(1)
except Exception as e:
    print(f"Caught unexpected exception: {type(e).__name__}: {e}")
    sys.exit(1)

print("Did not catch ValueError")
sys.exit(1)
"""

    # Run the subprocess
    # Ensure we run from the repository root so that "webui/src" path is valid
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))

    # Clear the relevant env vars for the subprocess just in case they are set in the parent process
    env = os.environ.copy()
    env.pop("WEBUI_ADMIN_USER", None)
    env.pop("WEBUI_ADMIN_PASSWORD", None)

    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        cwd=repo_root,
        env=env
    )

    if result.returncode != 0:
        print("Test failed!")
        print("STDOUT:", result.stdout)
        print("STDERR:", result.stderr)
        sys.exit(1)

    print("Test passed: ValueError was raised as expected.")

if __name__ == "__main__":
    test_missing_env_vars()
