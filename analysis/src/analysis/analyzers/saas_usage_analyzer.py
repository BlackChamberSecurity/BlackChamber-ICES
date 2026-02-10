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
Analyzer: SaaS Usage Classification

Domain-first architecture (CPU-optimized):
  1. Header signals  — structured metadata (always collected)
  2. Domain lookup   — O(1) match against known SaaS vendor catalog
  3. NLP (gated)     — zero-shot classifier ONLY for known SaaS vendors

The NLP step is a simple binary:
  - "usage"     — email indicates active SaaS use (account changes, OTP,
                   billing, alerts, reports, etc.)
  - "marketing" — newsletters, promotional content

Observations produced:
    is_saas           (boolean)  — sender identified as SaaS provider
    saas_confidence   (text)     — "known" (domain match)
    provider          (text)     — matched SaaS vendor name
    provider_category (text)     — vendor's SaaS category
    provider_org      (text)     — vendor's parent organization
    category          (text)     — "usage", "marketing", "unknown" (SaaS only)
    confidence        (numeric)  — NLP confidence 0-100 (SaaS only)
    list_unsubscribe  (boolean)  — List-Unsubscribe header present
    auto_submitted    (boolean)  — Auto-Submitted header present
    bulk_precedence   (boolean)  — Precedence=bulk/list header present
    marketing_mailer  (text)     — detected marketing platform
"""
import json
import logging
import re
from html.parser import HTMLParser
from pathlib import Path

from analysis.analyzers._base import BaseAnalyzer
from analysis.models import AnalysisResult, EmailEvent, Observation
from analysis.nlp import get_nlp_classifier

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# HTML text extraction
# ---------------------------------------------------------------------------
class _HTMLTextExtractor(HTMLParser):
    """Extract plain text from HTML, stripping all tags."""
    def __init__(self):
        super().__init__()
        self._text = []
        self._skip = False

    def handle_starttag(self, tag, attrs):
        if tag in ("style", "script", "head"):
            self._skip = True

    def handle_endtag(self, tag):
        if tag in ("style", "script", "head"):
            self._skip = False

    def handle_data(self, data):
        if not self._skip:
            self._text.append(data)

    def get_text(self) -> str:
        return " ".join(self._text)


def _strip_html(html: str) -> str:
    """Convert HTML to plain text."""
    extractor = _HTMLTextExtractor()
    try:
        extractor.feed(html)
        text = extractor.get_text()
    except Exception:
        text = re.sub(r"<[^>]+>", " ", html)
    return re.sub(r"\s+", " ", text).strip()


# ---------------------------------------------------------------------------
# Vendor dataset — loaded once per worker process
# ---------------------------------------------------------------------------
_VENDOR_DATA = None


def _load_vendor_data():
    global _VENDOR_DATA
    if _VENDOR_DATA is None:
        data_path = Path(__file__).parent.parent / "data" / "saas_vendors.json"
        try:
            with open(data_path) as f:
                _VENDOR_DATA = json.load(f)
            app_count = _VENDOR_DATA.get("_meta", {}).get("app_count", 0)
            domain_count = _VENDOR_DATA.get("_meta", {}).get("domain_count", 0)
            logger.info(
                "Loaded vendor dataset: %d apps, %d domain entries",
                app_count, domain_count,
            )
        except FileNotFoundError:
            logger.warning("Vendor dataset not found at %s — enrichment disabled", data_path)
            _VENDOR_DATA = {"domain_index": {}, "apps": {}}
        except Exception as exc:
            logger.warning("Failed to load vendor dataset: %s — enrichment disabled", exc)
            _VENDOR_DATA = {"domain_index": {}, "apps": {}}
    return _VENDOR_DATA






_MARKETING_MAILERS = frozenset({
    "mailchimp", "sendgrid", "marketo", "hubspot",
    "pardot", "constant contact", "brevo", "mailgun",
    "customer.io", "iterable", "klaviyo",
})


# ---------------------------------------------------------------------------
# Domain normalization — canonical provider name from sender domain
# ---------------------------------------------------------------------------
_MULTI_PART_TLDS = frozenset({
    "co.uk", "co.in", "com.au", "co.jp", "co.kr", "com.br",
    "co.nz", "co.za", "com.mx", "com.sg", "com.hk",
})


def _extract_root_domain(domain: str) -> str:
    """Extract the registrable root domain, e.g. 'mail.creditkarma.com' → 'creditkarma.com'."""
    parts = domain.lower().strip().split(".")
    if len(parts) <= 2:
        return domain.lower().strip()

    # Check for multi-part TLDs (e.g. co.uk)
    last_two = ".".join(parts[-2:])
    if last_two in _MULTI_PART_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])

    return ".".join(parts[-2:])


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------
class SaaSUsageAnalyzer(BaseAnalyzer):
    """Classify emails as SaaS usage indicators vs marketing noise.

    Pipeline:
      1. Header signals — always collected
      2. Domain lookup  — instant match against known vendor catalog
      3. NLP classify   — only runs for known SaaS vendors
    """

    name = "saas_usage"
    description = "Identifies SaaS senders and classifies email as usage vs marketing"
    order = 50  # NLP — most expensive, runs last

    def analyze(self, email: EmailEvent) -> AnalysisResult:
        observations = []

        # --- Step 1: Header signals (always collected) ---
        observations.extend(self._collect_header_observations(email))

        # --- Step 2: Domain lookup (O(1)) ---
        is_saas = False
        vendor_obs = self._vendor_lookup(email.sender)

        if vendor_obs:
            is_saas = True
            observations.extend(vendor_obs)

        # --- Step 3: Emit is_saas determination ---
        observations.append(Observation(key="is_saas", value=is_saas, type="boolean"))
        if is_saas:
            observations.append(
                Observation(key="saas_confidence", value="known", type="text")
            )

        # --- Step 4: NLP classification (ONLY for known SaaS vendors) ---
        if is_saas:
            category, confidence = self._nlp_classify(email)
            # Adjust with header signals
            category, confidence = self._adjust_with_headers(
                category, confidence, observations
            )
            observations.append(Observation(key="category", value=category, type="text"))
            observations.append(Observation(key="confidence", value=confidence, type="numeric"))

        return AnalysisResult(analyzer=self.name, observations=observations)

    # ----- Header signals -----

    def _collect_header_observations(self, email: EmailEvent) -> list[Observation]:
        observations = []
        headers = email.headers

        if headers.get("List-Unsubscribe"):
            observations.append(
                Observation(key="list_unsubscribe", value=True, type="boolean")
            )

        precedence = headers.get("Precedence", "").lower()
        if precedence in ("bulk", "list"):
            observations.append(
                Observation(key="bulk_precedence", value=True, type="boolean")
            )

        auto_submitted = headers.get("Auto-Submitted", "").lower()
        if auto_submitted and auto_submitted != "no":
            observations.append(
                Observation(key="auto_submitted", value=True, type="boolean")
            )

        x_mailer = headers.get("X-Mailer", "").lower()
        for mailer in _MARKETING_MAILERS:
            if mailer in x_mailer:
                observations.append(
                    Observation(key="marketing_mailer", value=mailer, type="text")
                )
                break

        return observations

    # ----- Domain lookup (O(1)) -----

    def _vendor_lookup(self, sender: str) -> list[Observation]:
        """Check sender domain against known SaaS vendor catalog."""
        if not sender:
            return []

        vendor_data = _load_vendor_data()
        domain_index = vendor_data.get("domain_index", {})
        apps = vendor_data.get("apps", {})

        domain = sender.lower().split("@")[-1] if "@" in sender else sender.lower()

        # Walk up the domain hierarchy for a match
        app_id = None
        parts = domain.split(".")
        for i in range(len(parts) - 1):
            candidate = ".".join(parts[i:])
            if candidate in domain_index:
                app_id = domain_index[candidate]
                break

        if app_id and app_id in apps:
            app = apps[app_id]
            return [
                Observation(key="provider", value=app.get("name", ""), type="text"),
                Observation(key="provider_category", value=app.get("category", ""), type="text"),
                Observation(key="provider_org", value=app.get("organization", "unknown"), type="text"),
            ]

        return []


    # ----- NLP classification -----

    def _nlp_classify(self, email: EmailEvent) -> tuple[str, int]:
        """Classify a SaaS email as usage or marketing using zero-shot NLP."""
        classifier = get_nlp_classifier()
        if classifier is None:
            return "unknown", 0

        body_text = email.body.content or ""
        if email.body.content_type == "html" or "<" in body_text[:50]:
            body_text = _strip_html(body_text)

        text = f"Subject: {email.subject or '(no subject)'}\n\n"
        text += body_text[:500]

        candidate_labels = [
            "account activity, password reset, security alert, billing receipt, or system report",
            "marketing newsletter or promotional content",
        ]

        try:
            result = classifier(text, candidate_labels, multi_label=False)
            top_label = result["labels"][0]
            top_score = result["scores"][0]

            if "account" in top_label or "activity" in top_label:
                return "usage", int(top_score * 100)
            else:
                return "marketing", int(top_score * 100)

        except Exception as exc:
            logger.warning("NLP classification failed: %s", exc)
            return "unknown", 0

    # ----- Score adjustment -----

    def _adjust_with_headers(
        self, category: str, confidence: int, observations: list[Observation]
    ) -> tuple[str, int]:
        """Nudge confidence based on header signals that corroborate or contradict."""
        has_list_unsub = any(o.key == "list_unsubscribe" for o in observations)
        has_bulk = any(o.key == "bulk_precedence" for o in observations)
        has_auto = any(o.key == "auto_submitted" for o in observations)

        marketing_signals = (1 if has_list_unsub else 0) + (1 if has_bulk else 0)
        usage_signals = 1 if has_auto else 0

        if category == "usage" and usage_signals > 0:
            confidence = min(confidence + usage_signals * 5, 100)
        elif category == "marketing" and marketing_signals > 0:
            confidence = min(confidence + marketing_signals * 5, 100)

        # Contradictory signals reduce confidence
        if category == "usage" and marketing_signals > usage_signals:
            confidence = max(confidence - marketing_signals * 5, 40)
        elif category == "marketing" and usage_signals > marketing_signals:
            confidence = max(confidence - usage_signals * 5, 40)

        return category, confidence
