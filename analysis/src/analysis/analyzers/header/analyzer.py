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
Analyzer: Email Header Authentication

Checks SPF, DKIM, and DMARC results from the email's authentication headers.

Observations produced:
    spf       (pass_fail)  — "pass" or "fail"
    dkim      (pass_fail)  — "pass" or "fail"
    dmarc     (pass_fail)  — "pass" or "fail"
    sender_mismatch (boolean) — envelope vs header domain mismatch
    envelope_domain (text) — Return-Path domain (when available)
"""
from analysis.analyzers._base import BaseAnalyzer
from analysis.models import AnalysisResult, EmailEvent, Observation


class HeaderAnalyzer(BaseAnalyzer):
    """Check email authentication headers (SPF, DKIM, DMARC)."""

    name = "header_auth"
    description = "Validates SPF, DKIM, and DMARC authentication results"
    order = 10  # cheapest check — run first

    def analyze(self, email: EmailEvent) -> AnalysisResult:
        observations = []

        auth_results = email.headers.get("Authentication-Results", "").lower()
        spf_header = email.headers.get("Received-SPF", "").lower()

        # --- SPF ---
        spf_pass = "spf=pass" in auth_results or "pass" in spf_header
        spf_fail = "spf=fail" in auth_results or "spf=softfail" in auth_results
        if spf_fail:
            observations.append(Observation(key="spf", value="fail", type="pass_fail"))
        elif spf_pass:
            observations.append(Observation(key="spf", value="pass", type="pass_fail"))
        elif auth_results:
            observations.append(Observation(key="spf", value="fail", type="pass_fail"))

        # --- DKIM ---
        dkim_pass = "dkim=pass" in auth_results
        dkim_fail = "dkim=fail" in auth_results
        if dkim_fail:
            observations.append(Observation(key="dkim", value="fail", type="pass_fail"))
        elif dkim_pass:
            observations.append(Observation(key="dkim", value="pass", type="pass_fail"))
        elif auth_results:
            observations.append(Observation(key="dkim", value="fail", type="pass_fail"))

        # --- DMARC ---
        dmarc_pass = "dmarc=pass" in auth_results
        dmarc_fail = "dmarc=fail" in auth_results
        if dmarc_fail:
            observations.append(Observation(key="dmarc", value="fail", type="pass_fail"))
        elif dmarc_pass:
            observations.append(Observation(key="dmarc", value="pass", type="pass_fail"))
        elif auth_results:
            observations.append(Observation(key="dmarc", value="fail", type="pass_fail"))

        # --- Sender mismatch ---
        envelope_from = email.headers.get("Return-Path", "").strip("<>")
        header_from = email.sender
        if envelope_from and header_from:
            env_domain = envelope_from.split("@")[-1].strip().lower()
            hdr_domain = header_from.split("@")[-1].lower()
            mismatch = env_domain != hdr_domain
            observations.append(
                Observation(key="sender_mismatch", value=mismatch, type="boolean")
            )
            if mismatch:
                observations.append(
                    Observation(key="envelope_domain", value=env_domain, type="text")
                )

        return AnalysisResult(analyzer=self.name, observations=observations)
