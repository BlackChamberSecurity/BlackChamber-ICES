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
Analyzer: URL Safety

Extracts URLs from the email body and checks for phishing indicators.

Observations produced:
    urls_found        (numeric)  — total URLs in body
    ip_urls_found     (numeric)  — URLs using raw IP addresses
    suspicious_tlds   (text)     — comma-separated list of suspicious TLDs found
    shorteners_found  (numeric)  — count of URL shortener links
    homoglyph_domains (text)     — comma-separated lookalike domains
    excessive_subdomains (numeric) — count of URLs with >4 subdomain levels
"""
import re
from urllib.parse import urlparse

from analysis.analyzers._base import BaseAnalyzer
from analysis.models import AnalysisResult, EmailEvent, Observation


SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".work", ".click", ".loan",
    ".gq", ".ml", ".cf", ".tk", ".ga", ".buzz", ".surf",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
}

URL_PATTERN = re.compile(
    r'https?://[^\s<>"\')\]]+',
    re.IGNORECASE,
)

IP_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')


class URLAnalyzer(BaseAnalyzer):
    """Check URLs in the email body for phishing indicators."""

    name = "url_check"
    description = "Detects suspicious URLs, phishing patterns, and URL shorteners"
    order = 20  # regex-based, fast

    def analyze(self, email: EmailEvent) -> AnalysisResult:
        body_text = email.body.content or ""
        urls = URL_PATTERN.findall(body_text)

        observations = [
            Observation(key="urls_found", value=len(urls), type="numeric"),
        ]

        if not urls:
            return AnalysisResult(analyzer=self.name, observations=observations)

        ip_urls = 0
        suspicious_tlds = []
        shorteners = 0
        homoglyph_domains = []
        excessive_subs = 0

        for url in urls:
            try:
                parsed = urlparse(url)
                hostname = parsed.hostname or ""
                hostname_lower = hostname.lower()
            except Exception:
                continue

            # IP address URLs
            if IP_PATTERN.match(hostname):
                ip_urls += 1

            # Suspicious TLDs
            for tld in SUSPICIOUS_TLDS:
                if hostname_lower.endswith(tld):
                    if tld not in suspicious_tlds:
                        suspicious_tlds.append(tld)
                    break

            # Shorteners
            if hostname_lower in SHORTENERS:
                shorteners += 1

            # Homoglyphs
            lookalike = self._check_homoglyphs(hostname_lower)
            if lookalike and lookalike not in homoglyph_domains:
                homoglyph_domains.append(lookalike)

            # Excessive subdomains
            if len(hostname_lower.split(".")) > 4:
                excessive_subs += 1

        observations.append(
            Observation(key="ip_urls_found", value=ip_urls, type="numeric")
        )
        if suspicious_tlds:
            observations.append(
                Observation(key="suspicious_tlds", value=",".join(suspicious_tlds), type="text")
            )
        observations.append(
            Observation(key="shorteners_found", value=shorteners, type="numeric")
        )
        if homoglyph_domains:
            observations.append(
                Observation(key="homoglyph_domains", value=",".join(homoglyph_domains), type="text")
            )
        if excessive_subs:
            observations.append(
                Observation(key="excessive_subdomains", value=excessive_subs, type="numeric")
            )

        return AnalysisResult(analyzer=self.name, observations=observations)

    def _check_homoglyphs(self, hostname: str) -> str:
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
        substitutions = {
            "0": "o", "1": "l", "l": "i", "rn": "m",
            "vv": "w", "5": "s", "3": "e",
        }
        normalised = hostname
        for fake, real in substitutions.items():
            normalised = normalised.replace(fake, real)
        for brand, domain in brands.items():
            if brand in normalised and brand not in hostname:
                return domain
        return ""
