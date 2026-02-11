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
Analyzer: Reputation Lookup

Checks the sender's IP and domain against multiple DNS-based blocklists (DNSBLs).

Supported Providers:
  - Spamhaus ZEN (zen.spamhaus.org) — Combined IP list (SBL, XBL, PBL)
  - Spamhaus DBL (dbl.spamhaus.org) — Domain blocklist
  - SpamCop (bl.spamcop.net) — IP blocklist based on spam reports
  - NiX Spam (ix.dnsbl.manitu.net) — IP blocklist (generic)

Observations produced:
    sender_ip         (text)      — IP address extracted from Received headers
    ip_listed         (boolean)   — True if sender IP is on ANY supported list
    domain_listed     (boolean)   — True if sender domain is on ANY supported list

    # Per-provider details (if listed):
    <provider>_listed (boolean)   — True if specific provider listed the IP/domain
    <provider>_code   (text)      — The return code label (e.g. "SBL", "Listed")

    reputation_error  (text)      — If DNS lookup failed unexpectedly
"""
import ipaddress
import logging
import re
import socket
import os
from typing import Optional

try:
    import redis
except ImportError:
    redis = None

from analysis.analyzers._base import BaseAnalyzer
from analysis.models import AnalysisResult, EmailEvent, Observation

logger = logging.getLogger(__name__)

# --- Configuration ---

# Return code → human-readable label
ZEN_CODES = {
    "127.0.0.2": "SBL",
    "127.0.0.3": "SBL-CSS",
    "127.0.0.4": "XBL-CBL",
    "127.0.0.5": "XBL-CBL",
    "127.0.0.6": "XBL-CBL",
    "127.0.0.7": "XBL-CBL",
    "127.0.0.9": "SBL-DROP",
    "127.0.0.10": "PBL",
    "127.0.0.11": "PBL",
}

DBL_CODES = {
    "127.0.1.2": "spam-domain",
    "127.0.1.4": "phish-domain",
    "127.0.1.5": "malware-domain",
    "127.0.1.6": "botnet-cc-domain",
    "127.0.1.102": "abused-legit-spam",
    "127.0.1.103": "abused-legit-registrar",
    "127.0.1.104": "abused-legit-phish",
    "127.0.1.105": "abused-legit-malware",
    "127.0.1.106": "abused-legit-botnet",
}

GENERIC_CODES = {
    "127.0.0.2": "Listed",
}

PROVIDERS = [
    {
        "id": "spamhaus_zen",
        "type": "ip",
        "zone": "zen.spamhaus.org",
        "codes": ZEN_CODES,
    },
    {
        "id": "spamcop",
        "type": "ip",
        "zone": "bl.spamcop.net",
        "codes": GENERIC_CODES,
    },
    {
        "id": "nix_spam",
        "type": "ip",
        "zone": "ix.dnsbl.manitu.net",
        "codes": GENERIC_CODES,
    },
    {
        "id": "spamhaus_dbl",
        "type": "domain",
        "zone": "dbl.spamhaus.org",
        "codes": DBL_CODES,
    },
]

# Regex to pull IPs from Received headers
_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

# DNS query timeout (seconds)
_DNS_TIMEOUT = 2.0

# Redis Cache TTL (seconds)
_CACHE_TTL = 3600  # 1 hour

_REDIS_CLIENT = None


def _get_redis_client() -> Optional["redis.Redis"]:
    """Get a Redis client if available (singleton)."""
    global _REDIS_CLIENT
    if redis is None:
        return None
    if _REDIS_CLIENT is not None:
        return _REDIS_CLIENT

    try:
        url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        # Create a client with a connection pool
        _REDIS_CLIENT = redis.from_url(url, decode_responses=True)
        return _REDIS_CLIENT
    except Exception as e:
        logger.warning("Failed to connect to Redis: %s", e)
        return None


def _extract_sender_ip(headers: dict) -> Optional[str]:
    """Extract the originating public IP from Received headers.

    Walks the Received chain (bottom-up = first hop) and returns the
    first public IP found. Private/reserved ranges are skipped.
    """
    received = headers.get("Received", "")
    # If multiple Received headers are concatenated, split on common delimiters
    if isinstance(received, list):
        received = "\n".join(received)

    for match in _IP_RE.finditer(received):
        ip_str = match.group(1)
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip.is_global:
                return ip_str
        except ValueError:
            continue
    return None


def _dnsbl_lookup(query: str, cache_key: str = None) -> Optional[str]:
    """Perform a DNSBL lookup and return the first A record, or None.

    Uses Redis caching if available.
    """
    # Check cache
    r = _get_redis_client()
    if r and cache_key:
        try:
            cached = r.get(cache_key)
            if cached:
                # If cached value is "NXDOMAIN", treat as None (not listed)
                if cached == "NXDOMAIN":
                    return None
                return cached
        except Exception as e:
            logger.warning("Redis cache error: %s", e)

    old_timeout = socket.getdefaulttimeout()
    result_val = None
    try:
        socket.setdefaulttimeout(_DNS_TIMEOUT)
        result_val = socket.gethostbyname(query)
    except socket.gaierror:
        # NXDOMAIN = not listed (normal)
        result_val = None
    except socket.timeout:
        logger.debug("DNSBL lookup timed out: %s", query)
        result_val = None
    except Exception as e:
        logger.warning("DNSBL lookup error for %s: %s", query, e)
        result_val = None
    finally:
        socket.setdefaulttimeout(old_timeout)

    # Cache result
    if r and cache_key:
        try:
            # Cache positive result or specific negative marker
            val_to_cache = result_val if result_val else "NXDOMAIN"
            r.setex(cache_key, _CACHE_TTL, val_to_cache)
        except Exception as e:
            logger.warning("Redis set error: %s", e)

    return result_val


def _check_ip(ip: str, provider: dict) -> tuple[bool, str]:
    """Check an IP against a specific provider.

    Returns (is_listed, list_name).
    """
    # Reverse the octets: 1.2.3.4 → 4.3.2.1.zone
    reversed_ip = ".".join(ip.split(".")[::-1])
    query = f"{reversed_ip}.{provider['zone']}"
    cache_key = f"reputation:ip:{provider['id']}:{ip}"

    result = _dnsbl_lookup(query, cache_key)
    if result:
        label = provider["codes"].get(result, f"unknown({result})")
        return True, label
    return False, ""


def _check_domain(domain: str, provider: dict) -> tuple[bool, str]:
    """Check a domain against a specific provider.

    Returns (is_listed, category).
    """
    query = f"{domain}.{provider['zone']}"
    cache_key = f"reputation:domain:{provider['id']}:{domain}"

    result = _dnsbl_lookup(query, cache_key)
    if result:
        label = provider["codes"].get(result, f"unknown({result})")
        return True, label
    return False, ""


class ReputationAnalyzer(BaseAnalyzer):
    """Check sender reputation against multiple blocklists (Spamhaus, SpamCop, etc)."""

    name = "reputation"
    description = "Queries multiple DNSBLs for IP and Domain reputation"
    order = 15  # after header_auth (10), before url_check (20)

    def analyze(self, email: EmailEvent) -> AnalysisResult:
        observations: list[Observation] = []

        # --- IP Reputation ---
        sender_ip = _extract_sender_ip(email.headers)
        if sender_ip:
            observations.append(
                Observation(key="sender_ip", value=sender_ip, type="text")
            )

            any_ip_listed = False
            for provider in [p for p in PROVIDERS if p["type"] == "ip"]:
                try:
                    listed, label = _check_ip(sender_ip, provider)
                    if listed:
                        any_ip_listed = True
                        observations.append(
                            Observation(key=f"{provider['id']}_listed", value=True, type="boolean")
                        )
                        observations.append(
                            Observation(key=f"{provider['id']}_code", value=label, type="text")
                        )
                except Exception as exc:
                    logger.warning("Reputation lookup error for %s on %s: %s", sender_ip, provider['id'], exc)
                    observations.append(
                        Observation(key="reputation_error", value=f"{provider['id']}: {exc}", type="text")
                    )

            observations.append(
                Observation(key="ip_listed", value=any_ip_listed, type="boolean")
            )

        else:
            observations.append(
                Observation(key="sender_ip", value="not_found", type="text")
            )
            # If no IP found, ip_listed is technically unknown, but false is safer default for policy
            observations.append(
                Observation(key="ip_listed", value=False, type="boolean")
            )

        # --- Domain Reputation ---
        sender_domain = ""
        if email.sender and "@" in email.sender:
            sender_domain = email.sender.split("@")[-1].strip().lower()

        if sender_domain:
            any_domain_listed = False
            for provider in [p for p in PROVIDERS if p["type"] == "domain"]:
                try:
                    listed, label = _check_domain(sender_domain, provider)
                    if listed:
                        any_domain_listed = True
                        observations.append(
                            Observation(key=f"{provider['id']}_listed", value=True, type="boolean")
                        )
                        observations.append(
                            Observation(key=f"{provider['id']}_code", value=label, type="text")
                        )
                except Exception as exc:
                    logger.warning("Reputation lookup error for %s on %s: %s", sender_domain, provider['id'], exc)
                    observations.append(
                        Observation(key="reputation_error", value=f"{provider['id']}: {exc}", type="text")
                    )

            observations.append(
                Observation(key="domain_listed", value=any_domain_listed, type="boolean")
            )

        return AnalysisResult(analyzer=self.name, observations=observations)
