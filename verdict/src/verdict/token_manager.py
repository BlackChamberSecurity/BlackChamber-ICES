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
BlackChamber ICES — Multi-Tenant OAuth2 Token Manager

Acquires and caches OAuth2 access tokens per tenant using the client
credentials flow. Supports both multi-tenant (config.yaml) and
single-tenant (env var fallback) configurations.

Thread-safe: uses a lock per tenant to prevent thundering-herd issues
when multiple Celery threads need tokens simultaneously.
"""

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

import httpx

logger = logging.getLogger(__name__)

# How many seconds before expiry to proactively refresh
REFRESH_BUFFER_SECONDS = 300  # 5 minutes


@dataclass
class _CachedToken:
    """Internal cache entry for a single tenant's token."""
    access_token: str = ""
    expires_at: float = 0.0  # Unix timestamp

    @property
    def is_valid(self) -> bool:
        return self.access_token and time.time() < (self.expires_at - REFRESH_BUFFER_SECONDS)


@dataclass
class TenantCredentials:
    """Credentials for a single M365 tenant."""
    tenant_id: str
    client_id: str
    client_secret: str


class TokenManager:
    """Multi-tenant OAuth2 token manager using client credentials flow.

    Usage:
        # Multi-tenant (from config.yaml):
        manager = TokenManager(tenants={
            "tenant-id-1": TenantCredentials("tenant-id-1", "client-1", "secret-1"),
            "tenant-id-2": TenantCredentials("tenant-id-2", "client-2", "secret-2"),
        })
        token = manager.get_token("tenant-id-1")

        # Single-tenant (env var fallback):
        manager = TokenManager()
        token = manager.get_token()  # Uses M365_TENANT_ID env var
    """

    def __init__(self, tenants: Optional[dict[str, TenantCredentials]] = None):
        self._tenants: dict[str, TenantCredentials] = tenants or {}
        self._tokens: dict[str, _CachedToken] = {}
        self._locks: dict[str, threading.Lock] = {}
        self._global_lock = threading.Lock()

        # Single-tenant fallback from environment variables
        env_tenant = os.environ.get("M365_TENANT_ID", "")
        env_client = os.environ.get("M365_CLIENT_ID", "")
        env_secret = os.environ.get("M365_CLIENT_SECRET", "")
        if env_tenant and env_client and env_secret and env_tenant not in self._tenants:
            self._tenants[env_tenant] = TenantCredentials(
                tenant_id=env_tenant,
                client_id=env_client,
                client_secret=env_secret,
            )
            logger.info("TokenManager: loaded fallback credentials from env for tenant %s", env_tenant)

        logger.info("TokenManager initialised with %d tenant(s)", len(self._tenants))

    def _get_lock(self, tenant_id: str) -> threading.Lock:
        """Get or create a per-tenant lock."""
        if tenant_id not in self._locks:
            with self._global_lock:
                if tenant_id not in self._locks:
                    self._locks[tenant_id] = threading.Lock()
        return self._locks[tenant_id]

    def get_token(self, tenant_id: Optional[str] = None) -> str:
        """Get a valid access token for the given tenant.

        If tenant_id is None, uses the first (or only) configured tenant.
        Tokens are cached and refreshed automatically before expiry.

        Args:
            tenant_id: The M365 tenant ID to get a token for.

        Returns:
            A valid access token string.

        Raises:
            ValueError: If the tenant is not configured.
            RuntimeError: If token acquisition fails.
        """
        # Default to first tenant if not specified
        if tenant_id is None:
            if not self._tenants:
                raise ValueError("No tenants configured — set M365_TENANT_ID env var or pass tenants dict")
            tenant_id = next(iter(self._tenants))

        if tenant_id not in self._tenants:
            raise ValueError(f"No credentials configured for tenant: {tenant_id}")

        # Check cache
        cached = self._tokens.get(tenant_id)
        if cached and cached.is_valid:
            return cached.access_token

        # Acquire per-tenant lock and refresh
        lock = self._get_lock(tenant_id)
        with lock:
            # Double-check after acquiring lock
            cached = self._tokens.get(tenant_id)
            if cached and cached.is_valid:
                return cached.access_token

            return self._refresh_token(tenant_id)

    def _refresh_token(self, tenant_id: str) -> str:
        """Acquire a fresh token from Azure AD."""
        creds = self._tenants[tenant_id]
        url = f"https://login.microsoftonline.com/{creds.tenant_id}/oauth2/v2.0/token"

        try:
            with httpx.Client(timeout=30) as client:
                resp = client.post(url, data={
                    "grant_type": "client_credentials",
                    "client_id": creds.client_id,
                    "client_secret": creds.client_secret,
                    "scope": "https://graph.microsoft.com/.default",
                })
                resp.raise_for_status()

            data = resp.json()
            access_token = data["access_token"]
            expires_in = int(data.get("expires_in", 3600))

            self._tokens[tenant_id] = _CachedToken(
                access_token=access_token,
                expires_at=time.time() + expires_in,
            )

            logger.info(
                "Token refreshed for tenant %s (expires in %ds)",
                tenant_id, expires_in,
            )
            return access_token

        except httpx.HTTPStatusError as exc:
            raise RuntimeError(
                f"Token acquisition failed for tenant {tenant_id}: "
                f"HTTP {exc.response.status_code} — {exc.response.text}"
            ) from exc
        except Exception as exc:
            raise RuntimeError(
                f"Token acquisition failed for tenant {tenant_id}: {exc}"
            ) from exc
