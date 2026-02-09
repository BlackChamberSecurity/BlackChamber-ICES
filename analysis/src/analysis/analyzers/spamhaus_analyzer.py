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
Analyzer: Spamhaus Reputation Lookup

Checks the sender's IP and domain against Spamhaus DNS-based blocklists:

  ZEN (zen.spamhaus.org) — combined IP list:
    127.0.0.2   SBL   (direct spam sources)
    127.0.0.3   SBL   CSS component (snowshoe spam)
    127.0.0.4-7 XBL   (exploited hosts, botnets)
    127.0.0.10  PBL   (end-user ranges that shouldn't send mail)

  DBL (dbl.spamhaus.org) — domain list:
    127.0.1.2   spam domain
    127.0.1.4   phish domain
    127.0.1.5   malware domain
    127.0.1.6   botnet C&C domain
    127.0.1.102 abused legit spam
    127.0.1.103 abused legit spammer registrar
    127.0.1.104 abused legit phish
    127.0.1.105 abused legit malware
    127.0.1.106 abused legit botnet C&C

Observations produced:
    sender_ip         (text)      — IP address extracted from Received headers
    ip_listed         (boolean)   — True if sender IP is on a Spamhaus list
    ip_list           (text)      — which Spamhaus zone matched (SBL/XBL/PBL)
    domain_listed     (boolean)   — True if sender domain is on DBL
    domain_list       (text)      — which DBL category matched
    spamhaus_error    (text)      — if DNS lookup failed unexpectedly
"""
import ipaddress
import logging
import re
import socket
from typing import Optional

from analysis.analyzers._base import BaseAnalyzer
from analysis.models import AnalysisResult, EmailEvent, Observation

logger = logging.getLogger(__name__)

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

# Regex to pull IPs from Received headers
_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

# DNS query timeout (seconds)
_DNS_TIMEOUT = 2.0


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


def _dnsbl_lookup(query: str) -> Optional[str]:
    """Perform a DNSBL lookup and return the first A record, or None."""
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(_DNS_TIMEOUT)
        result = socket.gethostbyname(query)
        return result
    except socket.gaierror:
        # NXDOMAIN = not listed (normal)
        return None
    except socket.timeout:
        logger.debug("DNSBL lookup timed out: %s", query)
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)


def _check_ip(ip: str) -> tuple[bool, str]:
    """Check an IP against Spamhaus ZEN.

    Returns (is_listed, list_name).
    """
    # Reverse the octets: 1.2.3.4 → 4.3.2.1.zen.spamhaus.org
    reversed_ip = ".".join(ip.split(".")[::-1])
    query = f"{reversed_ip}.zen.spamhaus.org"
    result = _dnsbl_lookup(query)
    if result:
        label = ZEN_CODES.get(result, f"unknown({result})")
        return True, label
    return False, ""


def _check_domain(domain: str) -> tuple[bool, str]:
    """Check a domain against Spamhaus DBL.

    Returns (is_listed, category).
    """
    query = f"{domain}.dbl.spamhaus.org"
    result = _dnsbl_lookup(query)
    if result:
        label = DBL_CODES.get(result, f"unknown({result})")
        return True, label
    return False, ""


class SpamhausAnalyzer(BaseAnalyzer):
    """Check sender reputation against Spamhaus blocklists."""

    name = "spamhaus"
    description = "Queries Spamhaus ZEN (IP) and DBL (domain) blocklists"
    order = 15  # after header_auth (10), before url_check (20)

    def analyze(self, email: EmailEvent) -> AnalysisResult:
        observations: list[Observation] = []

        # --- IP reputation (ZEN) ---
        sender_ip = _extract_sender_ip(email.headers)
        if sender_ip:
            observations.append(
                Observation(key="sender_ip", value=sender_ip, type="text")
            )
            try:
                listed, list_name = _check_ip(sender_ip)
                observations.append(
                    Observation(key="ip_listed", value=listed, type="boolean")
                )
                if listed:
                    observations.append(
                        Observation(key="ip_list", value=list_name, type="text")
                    )
            except Exception as exc:
                logger.warning("Spamhaus ZEN lookup error for %s: %s", sender_ip, exc)
                observations.append(
                    Observation(key="spamhaus_error", value=f"zen: {exc}", type="text")
                )
        else:
            observations.append(
                Observation(key="sender_ip", value="not_found", type="text")
            )

        # --- Domain reputation (DBL) ---
        sender_domain = ""
        if email.sender and "@" in email.sender:
            sender_domain = email.sender.split("@")[-1].strip().lower()

        if sender_domain:
            try:
                listed, category = _check_domain(sender_domain)
                observations.append(
                    Observation(key="domain_listed", value=listed, type="boolean")
                )
                if listed:
                    observations.append(
                        Observation(key="domain_list", value=category, type="text")
                    )
            except Exception as exc:
                logger.warning("Spamhaus DBL lookup error for %s: %s", sender_domain, exc)
                observations.append(
                    Observation(key="spamhaus_error", value=f"dbl: {exc}", type="text")
                )

        return AnalysisResult(analyzer=self.name, observations=observations)
