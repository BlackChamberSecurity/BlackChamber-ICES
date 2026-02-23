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

"""
BlackChamber ICES WebUI — JWT Authentication

Simple JWT auth seeded from environment variables.
Designed for easy extension to RBAC by adding a ``role`` claim.
"""

import os
import secrets
from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SECRET_KEY = os.environ.get("WEBUI_JWT_SECRET", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 24

ADMIN_USER = os.environ.get("WEBUI_ADMIN_USER")
ADMIN_PASSWORD = os.environ.get("WEBUI_ADMIN_PASSWORD")

if not ADMIN_USER or not ADMIN_PASSWORD:
    raise ValueError("WEBUI_ADMIN_USER and WEBUI_ADMIN_PASSWORD must be set in environment")


# ---------------------------------------------------------------------------
# Token helpers
# ---------------------------------------------------------------------------

def create_token(username: str) -> str:
    """Create a JWT for the given username."""
    payload = {
        "sub": username,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRE_HOURS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str) -> dict:
    """Decode and validate a JWT.  Returns the payload dict.

    Raises ``JWTError`` on any validation failure.
    """
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])


def authenticate(username: str, password: str) -> str | None:
    """Validate credentials and return a JWT, or None on failure."""
    if secrets.compare_digest(username, ADMIN_USER) and secrets.compare_digest(password, ADMIN_PASSWORD):
        return create_token(username)
    return None
