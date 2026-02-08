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
Analyzer: Email Header Authentication

Checks SPF, DKIM, and DMARC results from the email's authentication headers.
These headers tell us whether the sending server is authorised to send on
behalf of the claimed sender domain.

What each check means:
- SPF:   "Is this server allowed to send email for this domain?"
- DKIM:  "Was this email cryptographically signed by the domain?"
- DMARC: "Does this email pass the domain's authentication policy?"

A "pass" result is good. Anything else is suspicious.
"""
from analysis.analyzers._base import BaseAnalyzer
from analysis.models import AnalysisResult, EmailEvent


class HeaderAnalyzer(BaseAnalyzer):
    """Check email authentication headers (SPF, DKIM, DMARC)."""

    name = "header_auth"
    description = "Validates SPF, DKIM, and DMARC authentication results"
    severity_weight = 70

    def analyze(self, email: EmailEvent) -> AnalysisResult:
        findings = []
        score = 0

        # Get the authentication-results header (set by receiving mail server)
        auth_results = email.headers.get("Authentication-Results", "").lower()
        # Also check individual headers that some servers set
        spf_header = email.headers.get("Received-SPF", "").lower()

        # --- SPF Check ---
        spf_pass = "spf=pass" in auth_results or "pass" in spf_header
        spf_fail = "spf=fail" in auth_results or "spf=softfail" in auth_results
        if spf_fail:
            score += 30
            findings.append("SPF check FAILED — sender server is not authorised")
        elif not spf_pass and auth_results:
            score += 10
            findings.append("SPF check did not pass clearly")

        # --- DKIM Check ---
        dkim_pass = "dkim=pass" in auth_results
        dkim_fail = "dkim=fail" in auth_results
        if dkim_fail:
            score += 30
            findings.append("DKIM signature FAILED — email may have been tampered with")
        elif not dkim_pass and auth_results:
            score += 10
            findings.append("DKIM signature not verified")

        # --- DMARC Check ---
        dmarc_pass = "dmarc=pass" in auth_results
        dmarc_fail = "dmarc=fail" in auth_results
        if dmarc_fail:
            score += 40
            findings.append("DMARC policy FAILED — high risk of spoofing")
        elif not dmarc_pass and auth_results:
            score += 10
            findings.append("DMARC policy not verified")

        # --- Sender mismatch check ---
        envelope_from = email.headers.get("Return-Path", "").strip("<>")
        header_from = email.sender
        if envelope_from and header_from:
            env_domain = envelope_from.split("@")[-1].strip().lower()
            hdr_domain = header_from.split("@")[-1].lower()
            if env_domain != hdr_domain:
                score += 20
                findings.append(
                    f"Envelope sender domain ({env_domain}) doesn't match "
                    f"header sender domain ({hdr_domain})"
                )

        # Cap at 100
        score = min(score, 100)

        return AnalysisResult(
            analyzer=self.name,
            score=score,
            findings=findings,
        )
