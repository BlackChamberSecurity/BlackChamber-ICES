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
BlackChamber ICES WebUI — FastAPI Application

Serves the React SPA and provides a JSON API for the message trip dashboard.
"""

import logging
import os
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from jose import JWTError
from pydantic import BaseModel

from webui.auth import authenticate, verify_token
from webui.queries import get_message_trip, get_saas_analytics, get_stats, list_messages

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(title="BlackChamber ICES", docs_url="/api/docs", openapi_url="/api/openapi.json")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------

PUBLIC_PATHS = {"/api/login", "/api/docs", "/api/openapi.json"}


async def get_current_user(request: Request) -> str:
    """Extract and validate JWT from the Authorization header."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Missing or invalid Authorization header")
    token = auth[7:]
    try:
        payload = verify_token(token)
        return payload["sub"]
    except (JWTError, KeyError):
        raise HTTPException(401, "Invalid or expired token")


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/api/login")
async def login(body: LoginRequest):
    token = authenticate(body.username, body.password)
    if not token:
        raise HTTPException(401, "Invalid credentials")
    return {"token": token, "username": body.username}


# ---------------------------------------------------------------------------
# API routes (protected)
# ---------------------------------------------------------------------------

@app.get("/api/messages")
async def api_messages(
    limit: int = 50,
    offset: int = 0,
    tenant: str | None = None,
    user: str = Depends(get_current_user),
):
    return list_messages(limit=limit, offset=offset, tenant=tenant)


@app.get("/api/messages/{message_id:path}")
async def api_message_detail(message_id: str, user: str = Depends(get_current_user)):
    trip = get_message_trip(message_id)
    if not trip:
        raise HTTPException(404, "Message not found")
    return trip


@app.get("/api/stats")
async def api_stats(user: str = Depends(get_current_user)):
    return get_stats()


@app.get("/api/saas-analytics")
async def api_saas_analytics(
    days: int = 30,
    tenant: str | None = None,
    user: str | None = None,
    provider: str | None = None,
    authed: str = Depends(get_current_user),
):
    return get_saas_analytics(days=days, tenant=tenant, user=user, provider=provider)


# ---------------------------------------------------------------------------
# SPA — serve React build
# ---------------------------------------------------------------------------

STATIC_DIR = Path(__file__).resolve().parent.parent.parent / "static"


if STATIC_DIR.is_dir():
    # Serve assets (JS, CSS, images)
    app.mount("/assets", StaticFiles(directory=STATIC_DIR / "assets"), name="assets")

    @app.get("/{path:path}")
    async def spa_catchall(path: str):
        """Serve the React SPA for all non-API routes."""
        # Try to serve the exact file first (e.g. favicon.ico, vite.svg)
        try:
            # Resolve to handle ../ and enforce that the file stays within STATIC_DIR
            file = (STATIC_DIR / path).resolve()
            if path and file.is_relative_to(STATIC_DIR.resolve()) and file.is_file():
                return FileResponse(file)
        except (ValueError, RuntimeError):
            # Path traversal attempt or invalid path
            pass

        # Otherwise serve index.html (client-side routing)
        return FileResponse(STATIC_DIR / "index.html")
else:
    @app.get("/")
    async def no_frontend():
        return JSONResponse(
            {"error": "Frontend not built. Run 'npm run build' in webui/frontend/"},
            status_code=503,
        )
