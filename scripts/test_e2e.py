#!/usr/bin/env python3

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
End-to-end test: Fetch a real email from Graph API, push it through
the analysis pipeline via Redis/Celery.

Usage: python3 scripts/test_e2e.py
"""
import json
import os
import sys
import uuid

import redis
import requests

def get_graph_token(tenant_id, client_id, client_secret):
    """Get an OAuth2 token for Graph API."""
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    resp = requests.post(url, data={
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials",
    })
    resp.raise_for_status()
    return resp.json()["access_token"]

def fetch_latest_email(token, user_email):
    """Fetch the most recent email with headers."""
    url = (
        f"https://graph.microsoft.com/v1.0/users/{user_email}/messages"
        f"?$top=1&$select=id,subject,from,body,internetMessageHeaders"
    )
    headers = {
        "Authorization": f"Bearer {token}",
        "Prefer": 'outlook.body-content-type="text"',
    }
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    messages = resp.json().get("value", [])
    if not messages:
        print("No messages found!")
        sys.exit(1)
    return messages[0]

def graph_to_email_event(msg, user_email, tenant_id):
    """Convert Graph API message to our EmailEvent format."""
    headers = {}
    for h in msg.get("internetMessageHeaders", []):
        headers[h["name"]] = h["value"]

    return {
        "message_id": msg["id"],
        "user_id": user_email,
        "tenant_id": tenant_id,
        "sender": msg.get("from", {}).get("emailAddress", {}).get("address", ""),
        "subject": msg.get("subject", ""),
        "body": {
            "content_type": msg.get("body", {}).get("contentType", "text"),
            "content": msg.get("body", {}).get("content", ""),
        },
        "headers": headers,
        "attachments": [],
    }

def publish_celery_task(rdb, queue_name, email_event):
    """Push an email event as a Celery-compatible task to Redis."""
    task_id = str(uuid.uuid4())

    task_body = json.dumps({
        "id": task_id,
        "task": "analysis.tasks.analyze_email",
        "args": [json.dumps(email_event)],
        "kwargs": {},
        "retries": 0,
        "eta": None,
    })

    msg = json.dumps({
        "body": task_body,
        "content-encoding": "utf-8",
        "content-type": "application/json",
        "headers": {
            "lang": "py",
            "task": "analysis.tasks.analyze_email",
            "id": task_id,
            "retries": 0,
        },
        "properties": {
            "correlation_id": task_id,
            "delivery_mode": 2,
            "delivery_tag": task_id,
            "body_encoding": "base64",
        },
    })

    rdb.lpush(queue_name, msg)
    return task_id

def main():
    # Load env
    tenant_id = os.environ.get("M365_TENANT_ID")
    client_id = os.environ.get("M365_CLIENT_ID")
    client_secret = os.environ.get("M365_CLIENT_SECRET")
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

    if not all([tenant_id, client_id, client_secret]):
        print("ERROR: Set M365_TENANT_ID, M365_CLIENT_ID, M365_CLIENT_SECRET")
        sys.exit(1)

    user_email = sys.argv[1] if len(sys.argv) > 1 else "John.Earle@MainMethod.AI"

    # 1. Get Graph token
    print(f"[1/4] Getting Graph API token...")
    token = get_graph_token(tenant_id, client_id, client_secret)
    print(f"       ✅ Token acquired")

    # 2. Fetch latest email
    print(f"[2/4] Fetching latest email for {user_email}...")
    msg = fetch_latest_email(token, user_email)
    print(f"       ✅ Subject: {msg.get('subject')}")
    print(f"       ✅ From: {msg.get('from', {}).get('emailAddress', {}).get('address')}")

    # 3. Convert to EmailEvent
    print(f"[3/4] Converting to EmailEvent...")
    event = graph_to_email_event(msg, user_email, tenant_id)
    print(f"       ✅ Headers: {len(event['headers'])} found")

    # 4. Push to Redis
    print(f"[4/4] Publishing to Redis queue 'emails'...")
    rdb = redis.from_url(redis_url)
    task_id = publish_celery_task(rdb, "emails", event)
    print(f"       ✅ Task ID: {task_id}")
    print()
    print("Done! Check analysis worker logs:")
    print("  docker compose logs -f analysis-worker")

if __name__ == "__main__":
    main()
