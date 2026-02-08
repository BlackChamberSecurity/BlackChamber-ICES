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
"""Backlog test: Fetch last 24h of emails from M365 and run the SaaS usage analyzer.

Usage:
    PYTHONPATH=analysis/src python3 scripts/backlog_test.py
"""
import json
import os
import sys
import urllib.request
import urllib.parse
from datetime import datetime, timedelta, timezone

# Add analysis source to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'analysis', 'src'))

from analysis.analyzers.saas_usage_analyzer import SaaSUsageAnalyzer
from analysis.models import EmailEvent, EmailBody


def get_access_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    """Get OAuth2 access token using client credentials flow."""
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = urllib.parse.urlencode({
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials",
    }).encode()

    req = urllib.request.Request(url, data=data, method="POST")
    with urllib.request.urlopen(req) as resp:
        result = json.loads(resp.read())
    return result["access_token"]


def graph_get(token: str, url: str) -> dict:
    """Make an authenticated GET request to Graph API."""
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def list_users(token: str) -> list[dict]:
    """List users with mailboxes."""
    url = "https://graph.microsoft.com/v1.0/users?$select=id,displayName,mail&$top=50"
    result = graph_get(token, url)
    return result.get("value", [])


def fetch_recent_emails(token: str, user_id: str, since: str) -> list[dict]:
    """Fetch emails received since the given ISO timestamp."""
    params = urllib.parse.urlencode({
        "$filter": f"receivedDateTime ge {since}",
        "$select": "id,subject,from,receivedDateTime,body,internetMessageHeaders",
        "$top": "50",
        "$orderby": "receivedDateTime desc",
    }, quote_via=urllib.parse.quote)
    url = f"https://graph.microsoft.com/v1.0/users/{user_id}/messages?{params}"
    try:
        result = graph_get(token, url)
        return result.get("value", [])
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return []
        raise


def graph_msg_to_email_event(msg: dict, user_id: str, tenant_id: str) -> EmailEvent:
    """Convert a Graph API message to an EmailEvent."""
    from_data = msg.get("from", {}).get("emailAddress", {})

    # Extract headers into a dict
    headers = {}
    for h in msg.get("internetMessageHeaders", []) or []:
        headers[h["name"]] = h["value"]

    body_data = msg.get("body", {})

    return EmailEvent(
        message_id=msg.get("id", ""),
        user_id=user_id,
        tenant_id=tenant_id,
        sender=from_data.get("address", ""),
        sender_name=from_data.get("name", ""),
        subject=msg.get("subject", ""),
        body=EmailBody(
            content_type=body_data.get("contentType", "text"),
            content=body_data.get("content", ""),
        ),
        headers=headers,
        received_at=msg.get("receivedDateTime", ""),
    )


def main():
    # Load creds from .env
    env_path = os.path.join(os.path.dirname(__file__), '..', '.env')
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, val = line.split('=', 1)
                    os.environ.setdefault(key.strip(), val.strip())

    tenant_id = os.environ.get("M365_TENANT_ID_1", "")
    client_id = os.environ.get("M365_CLIENT_ID_1", "")
    client_secret = os.environ.get("M365_CLIENT_SECRET_1", "")

    if not all([tenant_id, client_id, client_secret]):
        print("ERROR: M365 credentials not found in .env")
        sys.exit(1)

    print("Authenticating with M365...")
    token = get_access_token(tenant_id, client_id, client_secret)
    print("✓ Authenticated\n")

    # Get users
    print("Fetching users...")
    users = list_users(token)
    print(f"Found {len(users)} users\n")

    # Time window: last 24 hours
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"Fetching emails since {since}\n")

    # Initialize analyzer
    analyzer = SaaSUsageAnalyzer()

    # Results collection
    all_results = []

    for user in users:
        user_mail = user.get("mail", "") or user.get("displayName", "")
        user_id = user["id"]
        print(f"--- {user_mail} ---")

        try:
            messages = fetch_recent_emails(token, user_id, since)
        except Exception as e:
            print(f"  Error fetching: {e}")
            continue

        if not messages:
            print("  No messages in last 24h")
            continue

        print(f"  {len(messages)} message(s)")

        for msg in messages:
            email = graph_msg_to_email_event(msg, user_id, tenant_id)
            result = analyzer.analyze(email)

            entry = {
                "user": user_mail,
                "sender": email.sender,
                "subject": email.subject[:80],
                "score": result.score,
                "category": result.category,
                "provider": result.provider,
                "findings": result.findings,
            }
            all_results.append(entry)

    # --- Summary ---
    print(f"\n{'='*80}")
    print(f"BACKLOG TEST RESULTS — {len(all_results)} emails analyzed")
    print(f"{'='*80}\n")

    if not all_results:
        print("No emails found in the last 24 hours.")
        return

    # Sort by score descending
    all_results.sort(key=lambda x: x["score"], reverse=True)

    # Table output
    print(f"{'Score':>5} | {'Category':^15} | {'Provider':^20} | {'Sender':^30} | Subject")
    print(f"{'-'*5}-+-{'-'*15}-+-{'-'*20}-+-{'-'*30}-+-{'-'*40}")

    for r in all_results:
        print(
            f"{r['score']:5d} | {r['category']:^15} | {r['provider'] or '—':^20} | "
            f"{r['sender'][:30]:^30} | {r['subject'][:50]}"
        )

    # Stats
    print(f"\n--- Summary ---")
    transactional = [r for r in all_results if r["category"] == "transactional"]
    marketing = [r for r in all_results if r["category"] == "marketing"]
    unknown = [r for r in all_results if r["category"] not in ("transactional", "marketing")]

    print(f"  Transactional (SaaS usage): {len(transactional)}")
    print(f"  Marketing (noise):          {len(marketing)}")
    print(f"  Unknown/unclassified:       {len(unknown)}")

    # Known vs unknown vendors
    with_vendor = [r for r in all_results if r["provider"]]
    without_vendor = [r for r in all_results if not r["provider"]]
    print(f"  Known vendor:               {len(with_vendor)}")
    print(f"  Unknown vendor:             {len(without_vendor)}")

    # Unique providers detected
    providers = set(r["provider"] for r in all_results if r["provider"])
    if providers:
        print(f"\n  SaaS providers detected: {', '.join(sorted(providers))}")

    # Save full results
    results_path = os.path.join(os.path.dirname(__file__), '..', 'backlog_results.json')
    with open(results_path, 'w') as f:
        json.dump(all_results, f, indent=2)
    print(f"\n  Full results saved to: backlog_results.json")


if __name__ == "__main__":
    main()
