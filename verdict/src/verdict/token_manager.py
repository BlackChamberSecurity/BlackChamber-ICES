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
BCEM Verdict Worker — Token Manager

Thread-safe OAuth2 token manager using the client credentials flow.
Replaces the static M365_ACCESS_TOKEN env var with automatic token
acquisition and refresh.

Tokens are cached and refreshed 5 minutes before expiry to avoid
requests failing due to token expiration mid-batch.
"""
import logging
import os
import threading
import time

import httpx

logger = logging.getLogger(__name__)

# Buffer before token expiry to trigger refresh (seconds)
REFRESH_BUFFER_SECONDS = 300  # 5 minutes


class TokenManager:
    """
    Acquires and caches an OAuth2 access token using the client credentials flow.

    Usage:
        manager = TokenManager()
        token = manager.get_token()   # Always returns a valid token
    """

    def __init__(
        self,
        tenant_id: str = "",
        client_id: str = "",
        client_secret: str = "",
    ):
        self.tenant_id = tenant_id or os.environ.get("M365_TENANT_ID", "")
        self.client_id = client_id or os.environ.get("M365_CLIENT_ID", "")
        self.client_secret = client_secret or os.environ.get("M365_CLIENT_SECRET", "")

        self.token_url = (
            f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        )

        self._token: str = ""
        self._expires_at: float = 0.0
        self._lock = threading.Lock()

    def get_token(self) -> str:
        """
        Return a valid access token, refreshing if needed.

        Thread-safe: multiple Celery worker threads can call this safely.
        """
        if self._is_valid():
            return self._token

        with self._lock:
            # Double-check after acquiring lock
            if self._is_valid():
                return self._token

            self._refresh()
            return self._token

    def _is_valid(self) -> bool:
        """Check if the cached token is still valid (with buffer)."""
        return (
            self._token != ""
            and time.time() < (self._expires_at - REFRESH_BUFFER_SECONDS)
        )

    def _refresh(self) -> None:
        """Acquire a new token from Azure AD."""
        if not all([self.tenant_id, self.client_id, self.client_secret]):
            logger.warning(
                "Token manager: missing credentials "
                "(M365_TENANT_ID, M365_CLIENT_ID, M365_CLIENT_SECRET). "
                "Batch actions will fail."
            )
            return

        try:
            response = httpx.post(
                self.token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "scope": "https://graph.microsoft.com/.default",
                },
                timeout=10.0,
            )
            response.raise_for_status()

            data = response.json()
            self._token = data["access_token"]
            # expires_in is in seconds from now
            expires_in = int(data.get("expires_in", 3600))
            self._expires_at = time.time() + expires_in

            logger.info(
                "Token refreshed: expires_in=%ds, refresh_at=%ds",
                expires_in,
                expires_in - REFRESH_BUFFER_SECONDS,
            )

        except httpx.HTTPError as exc:
            logger.error("Token refresh failed: %s", exc)
            # Keep existing token if it hasn't fully expired yet
            if self._token and time.time() < self._expires_at:
                logger.warning("Using existing token (still valid for %ds)",
                               int(self._expires_at - time.time()))
            else:
                self._token = ""
                self._expires_at = 0.0

        except (KeyError, ValueError) as exc:
            logger.error("Token response parsing failed: %s", exc)
            self._token = ""
            self._expires_at = 0.0
