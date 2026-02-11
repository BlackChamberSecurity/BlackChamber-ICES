#!/usr/bin/env python3
"""
Live Defender quarantine test.

Uses the ices_shared config loader (which expands env vars) and the
verdict TokenManager to acquire credentials, then calls the Defender
analyzedEmails/remediate API to soft-delete a specific email.
"""
import json
import sys

import httpx

from ices_shared.config import get_tenants
from verdict.token_manager import TokenManager, TenantCredentials


def main():
    # --- Build TokenManager from config ---
    tenants = {}
    for t in get_tenants():
        tid = t.get("tenant_id", "")
        cid = t.get("client_id", "")
        csecret = t.get("client_secret", "")
        if tid and cid and csecret:
            tenants[tid] = TenantCredentials(
                tenant_id=tid, client_id=cid, client_secret=csecret,
            )

    if not tenants:
        print("❌ No tenants found in config")
        sys.exit(1)

    manager = TokenManager(tenants=tenants)

    # Use the first tenant
    tenant_id = list(tenants.keys())[0]
    print(f"Tenant ID: {tenant_id}")

    # Acquire token
    token = manager.get_token(tenant_id)
    print(f"Token acquired (length={len(token)})")

    # --- Target message ---
    # The "VIP Offer" spam email from the backfill
    message_id = "AAMkAGY0NjBlYjU4LWU2OGEtNGIyNy05YjhmLTcwN2YwYjc0Y2NkMABGAAAAAAAFVLugc5SYQokwuMMXKzMVBwC46pWeTmPhRp-NaAClzBKuAAAAAAEMAAC46pWeTmPhRp-NaAClzBKuAAGzyd04AAA="
    recipient = "John.Earle@MainMethod.AI"

    print(f"\nQuarantining message:")
    print(f"  Message ID: {message_id[:60]}...")
    print(f"  Recipient:  {recipient}")
    print(f"  Subject:    Fwd: VIP Offer: €2000 Bonus Just for You")

    # --- Call Defender remediate API ---
    remediate_url = "https://graph.microsoft.com/beta/security/collaboration/analyzedEmails/remediate"

    body = {
        "displayName": "ICES Quarantine Test",
        "description": "BlackChamber ICES - live quarantine test",
        "severity": "high",
        "action": "softDelete",
        "remediateBy": "automation",
        "analyzedEmails": [
            {
                "networkMessageId": message_id,
                "recipientEmailAddress": recipient,
            }
        ],
    }

    print(f"\nPOST {remediate_url}")
    print(f"Body: {json.dumps(body, indent=2)}")
    print("\nSending...")

    try:
        resp = httpx.post(
            remediate_url,
            json=body,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            timeout=30,
        )
        print(f"\nHTTP {resp.status_code}")
        print(f"Response: {resp.text[:2000]}")

        if resp.status_code < 300:
            print("\n✅ Quarantine request accepted!")
        else:
            print(f"\n❌ Request failed: HTTP {resp.status_code}")

    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
