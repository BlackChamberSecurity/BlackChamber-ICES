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

import shutil
import tempfile
import unittest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

# ---------------------------------------------------------------------------
# Test Setup: Mock Dependencies
# ---------------------------------------------------------------------------
# This test runs in a restricted environment where some dependencies (fastapi,
# psycopg, etc.) might not be installed. We mock them to allow importing the
# application code and verify the logic of the path traversal fix.

sys.modules["fastapi"] = MagicMock()
sys.modules["fastapi.responses"] = MagicMock()
sys.modules["fastapi.staticfiles"] = MagicMock()
sys.modules["fastapi.middleware.cors"] = MagicMock()
sys.modules["pydantic"] = MagicMock()
sys.modules["jose"] = MagicMock()
sys.modules["psycopg"] = MagicMock()
sys.modules["psycopg.rows"] = MagicMock()
sys.modules["psycopg_pool"] = MagicMock()

# Setup mocks for what webui.main imports
from fastapi import FastAPI
from fastapi.responses import FileResponse

# Helper decorator to bypass FastAPI decorators in tests
def pass_through_decorator(*args, **kwargs):
    def decorator(func):
        return func
    return decorator

# Configure the mock app to use pass-through decorators
mock_app = MagicMock()
mock_app.get.side_effect = pass_through_decorator
mock_app.post.side_effect = pass_through_decorator

# Ensure FastAPI() returns our mock app
MockFastAPI = MagicMock(return_value=mock_app)
sys.modules["fastapi"].FastAPI = MockFastAPI

# ---------------------------------------------------------------------------
# Import Module Under Test
# ---------------------------------------------------------------------------

# Patch environment and filesystem checks to ensure successful import
with patch("pathlib.Path.is_dir", return_value=True):
    with patch.dict("os.environ", {
        "WEBUI_JWT_SECRET": "testsecret",
        "WEBUI_ADMIN_USER": "admin",
        "WEBUI_ADMIN_PASSWORD": "password"
    }):
        import webui.main


# ---------------------------------------------------------------------------
# Test Case
# ---------------------------------------------------------------------------

class TestPathTraversal(unittest.IsolatedAsyncioTestCase):
    """
    Verifies that the SPA catch-all route correctly prevents path traversal attacks
    by validating that resolved paths remain within the STATIC_DIR.
    """

    @classmethod
    def setUpClass(cls):
        # Create a temporary directory structure for static files
        cls.test_dir = tempfile.mkdtemp()
        cls.static_path = Path(cls.test_dir) / "static"
        cls.static_path.mkdir()

        # Create legitimate files
        (cls.static_path / "index.html").write_text("<html>Index</html>")
        (cls.static_path / "safe.txt").write_text("Safe Content")

        # Create a secret file outside the static directory
        cls.secret_path = Path(cls.test_dir) / "secret.txt"
        cls.secret_path.write_text("SUPER_SECRET_DATA")

        # Overwrite STATIC_DIR in the module to point to our temp dir
        webui.main.STATIC_DIR = cls.static_path

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.test_dir)

    async def test_safe_access(self):
        """Verify accessing a valid file within the static directory."""
        webui.main.FileResponse.reset_mock()
        await webui.main.spa_catchall("safe.txt")

        call_args = webui.main.FileResponse.call_args
        if call_args:
            args, _ = call_args
            self.assertEqual(args[0].resolve(), (self.static_path / "safe.txt").resolve())
        else:
            self.fail("FileResponse was not called for valid file")

    async def test_traversal_attack(self):
        """Verify that attempting to access a file outside the directory falls back to index.html."""
        webui.main.FileResponse.reset_mock()
        await webui.main.spa_catchall("../secret.txt")

        # Should verify path is not relative to static dir and return index.html
        call_args = webui.main.FileResponse.call_args
        if call_args:
            args, _ = call_args
            self.assertEqual(args[0].resolve(), (self.static_path / "index.html").resolve())
        else:
            self.fail("FileResponse was not called for traversal attempt")

    async def test_nested_traversal(self):
        """Verify complex traversal paths are handled correctly."""
        webui.main.FileResponse.reset_mock()
        await webui.main.spa_catchall("foo/../../secret.txt")

        call_args = webui.main.FileResponse.call_args
        if call_args:
            args, _ = call_args
            self.assertEqual(args[0].resolve(), (self.static_path / "index.html").resolve())
        else:
            self.fail("FileResponse was not called for nested traversal")

if __name__ == "__main__":
    unittest.main()
