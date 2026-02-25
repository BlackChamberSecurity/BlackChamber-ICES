import subprocess
import sys
import os

def test_missing_env_vars():
    # This command tries to import webui.auth without setting environment variables.
    # It expects the import to fail with a ValueError.
    script = """
import sys
import os
from unittest.mock import MagicMock

sys.modules['jose'] = MagicMock()
sys.modules['jose.jwt'] = MagicMock()
sys.modules['jose.JWTError'] = Exception
sys.path.insert(0, os.path.abspath('webui/src'))

try:
    import webui.auth
except ValueError:
    sys.exit(0)
except Exception as e:
    print(f"Unexpected exception: {e}")
    sys.exit(1)

print("Did not raise ValueError")
sys.exit(1)
"""

    # Clear the relevant env vars to simulate a fresh environment
    env = os.environ.copy()
    env.pop("WEBUI_ADMIN_USER", None)
    env.pop("WEBUI_ADMIN_PASSWORD", None)

    # Run the subprocess, passing the script via stdin
    result = subprocess.run([sys.executable, "-"], input=script, env=env, capture_output=True, text=True)

    if result.returncode == 0:
        print("Success: ValueError raised on missing config")
    else:
        print("Failure: ValueError NOT raised on missing config")
        print("STDOUT:", result.stdout)
        print("STDERR:", result.stderr)
        sys.exit(1)

if __name__ == "__main__":
    test_missing_env_vars()
