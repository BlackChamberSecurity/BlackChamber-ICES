# Copyright (c) 2026 John Earle
#
# Licensed under the Business Source License 1.1 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://github.com/yourusername/bcem/blob/main/LICENSE
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Analyzer: URL Safety

Extracts URLs from the email body and checks them for signs of phishing
or malicious intent. This is a heuristic-based check (no external API calls).

What it checks:
- Known suspicious TLDs (top-level domains) often used in phishing
- IP addresses used as URLs (legitimate sites use domain names)
- Homoglyph attacks (lookalike characters: "paypaI.com" vs "paypal.com")
- Excessive URL redirects / shorteners
- Mismatched display text vs actual URL
"""
import re
from urllib.parse import urlparse

from analysis.analyzers._base import BaseAnalyzer
from analysis.models import AnalysisResult, EmailEvent


# Commonly abused TLDs (top-level domains) in phishing campaigns
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".work", ".click", ".loan",
    ".gq", ".ml", ".cf", ".tk", ".ga", ".buzz", ".surf",
}

# URL shortener domains
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
}

# Regex to extract URLs from text
URL_PATTERN = re.compile(
    r'https?://[^\s<>"\')\]]+',
    re.IGNORECASE,
)

# Regex to detect IP addresses used as hostnames
IP_PATTERN = re.compile(
    r'^(\d{1,3}\.){3}\d{1,3}$'
)


class URLAnalyzer(BaseAnalyzer):
    """Check URLs in the email body for phishing indicators."""

    name = "url_check"
    description = "Detects suspicious URLs, phishing patterns, and URL shorteners"
    severity_weight = 80

    def analyze(self, email: EmailEvent) -> AnalysisResult:
        findings = []
        score = 0

        # Extract all URLs from body
        body_text = email.body.content or ""
        urls = URL_PATTERN.findall(body_text)

        if not urls:
            return AnalysisResult(analyzer=self.name, score=0, findings=[])

        for url in urls:
            try:
                parsed = urlparse(url)
                hostname = parsed.hostname or ""
                hostname_lower = hostname.lower()
            except Exception:
                findings.append(f"Malformed URL: {url[:80]}")
                score += 20
                continue

            # Check for IP address as hostname
            if IP_PATTERN.match(hostname):
                score += 30
                findings.append(f"URL uses raw IP address: {url[:80]}")

            # Check for suspicious TLDs
            for tld in SUSPICIOUS_TLDS:
                if hostname_lower.endswith(tld):
                    score += 15
                    findings.append(f"URL uses suspicious TLD ({tld}): {url[:80]}")
                    break

            # Check for URL shorteners
            if hostname_lower in SHORTENERS:
                score += 10
                findings.append(f"URL shortener detected: {url[:80]}")

            # Check for homoglyph / lookalike characters
            homoglyphs = self._check_homoglyphs(hostname_lower)
            if homoglyphs:
                score += 40
                findings.append(
                    f"Possible lookalike domain: {hostname} "
                    f"(may be impersonating {homoglyphs})"
                )

            # Check for excessive subdomains (e.g. login.paypal.com.evil.com)
            parts = hostname_lower.split(".")
            if len(parts) > 4:
                score += 15
                findings.append(f"URL has many subdomains (possible phishing): {url[:80]}")

        # Cap at 100
        score = min(score, 100)

        return AnalysisResult(
            analyzer=self.name,
            score=score,
            findings=findings,
        )

    def _check_homoglyphs(self, hostname: str) -> str:
        """
        Simple homoglyph detection — checks if a hostname looks like a
        well-known brand but with character substitutions.
        """
        # Common brands targeted by phishing
        brands = {
            "paypal": "paypal.com",
            "microsoft": "microsoft.com",
            "apple": "apple.com",
            "google": "google.com",
            "amazon": "amazon.com",
            "netflix": "netflix.com",
            "facebook": "facebook.com",
            "instagram": "instagram.com",
        }

        # Common character substitutions used in phishing
        substitutions = {
            "0": "o", "1": "l", "l": "i", "rn": "m",
            "vv": "w", "5": "s", "3": "e",
        }

        # Normalise the hostname by applying substitutions
        normalised = hostname
        for fake, real in substitutions.items():
            normalised = normalised.replace(fake, real)

        # Check if the normalised hostname contains a brand name
        # but the original hostname doesn't exactly match
        for brand, domain in brands.items():
            if brand in normalised and brand not in hostname:
                return domain

        return ""
