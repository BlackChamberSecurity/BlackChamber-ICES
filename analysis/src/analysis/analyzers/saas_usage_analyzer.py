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

NLP-first architecture:
  1. Header signals — structured metadata NLP can't see
  2. NLP classification — zero-shot transformer classifies email type
  3. Vendor enrichment — match sender domain against known vendor dataset

Observations produced:
    category          (text)     — "transactional", "marketing", "unknown"
    confidence        (numeric)  — NLP classification confidence (0-100)
    provider          (text)     — matched SaaS vendor name
    provider_category (text)     — vendor's SaaS category
    provider_org      (text)     — vendor's parent organization
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

logger = logging.getLogger(__name__)


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


# ---------------------------------------------------------------------------
# NLP classifier — lazy-loaded once per worker
# ---------------------------------------------------------------------------
_nlp_classifier = None


def _get_nlp_classifier():
    global _nlp_classifier
    if _nlp_classifier is None:
        try:
            from transformers import pipeline
            logger.info("Loading zero-shot classification model...")
            _nlp_classifier = pipeline(
                "zero-shot-classification",
                model="cross-encoder/nli-distilroberta-base",
                device=-1,
            )
            logger.info("NLP model loaded successfully")
        except Exception as exc:
            logger.warning("Failed to load NLP model: %s. Falling back to headers only.", exc)
            _nlp_classifier = False
    return _nlp_classifier if _nlp_classifier is not False else None


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------
class SaaSUsageAnalyzer(BaseAnalyzer):
    """Classify emails as SaaS usage indicators vs marketing noise."""

    name = "saas_usage"
    description = "Classifies emails as transactional SaaS usage vs marketing noise using NLP"
    order = 50  # NLP — most expensive, runs last

    def analyze(self, email: EmailEvent) -> AnalysisResult:
        observations = []

        # --- Step 1: Header signals ---
        observations.extend(self._collect_header_observations(email))

        # --- Step 2: NLP classification ---
        category, confidence = self._nlp_classify(email)
        observations.append(Observation(key="category", value=category, type="text"))
        observations.append(Observation(key="confidence", value=confidence, type="numeric"))

        # --- Step 3: Adjust with headers ---
        category, confidence = self._adjust_with_headers(
            category, confidence, observations
        )
        # Update the category/confidence observations with adjusted values
        for obs in observations:
            if obs.key == "category":
                obs.value = category
            elif obs.key == "confidence":
                obs.value = confidence

        # --- Step 4: Vendor enrichment ---
        observations.extend(self._vendor_observations(email.sender))

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
        marketing_mailers = [
            "mailchimp", "sendgrid", "marketo", "hubspot",
            "pardot", "constant contact",
        ]
        for mailer in marketing_mailers:
            if mailer in x_mailer:
                observations.append(
                    Observation(key="marketing_mailer", value=mailer, type="text")
                )
                break

        return observations

    # ----- NLP classification -----

    def _nlp_classify(self, email: EmailEvent) -> tuple[str, int]:
        classifier = _get_nlp_classifier()
        if classifier is None:
            return "unknown", 0

        body_text = email.body.content or ""
        if email.body.content_type == "html" or "<" in body_text[:50]:
            body_text = _strip_html(body_text)

        text = f"Subject: {email.subject or '(no subject)'}\n\n"
        text += body_text[:500]

        candidate_labels = [
            "automated notification from a software application",
            "marketing newsletter or promotional content",
        ]

        try:
            result = classifier(text, candidate_labels, multi_label=False)
            top_label = result["labels"][0]
            top_score = result["scores"][0]

            if "notification" in top_label:
                return "transactional", int(top_score * 100)
            else:
                return "marketing", int(top_score * 100)

        except Exception as exc:
            logger.warning("NLP classification failed: %s", exc)
            return "unknown", 0

    # ----- Score adjustment -----

    def _adjust_with_headers(
        self, category: str, confidence: int, observations: list[Observation]
    ) -> tuple[str, int]:
        has_list_unsub = any(o.key == "list_unsubscribe" for o in observations)
        has_bulk = any(o.key == "bulk_precedence" for o in observations)
        has_auto = any(o.key == "auto_submitted" for o in observations)

        marketing_signals = (1 if has_list_unsub else 0) + (1 if has_bulk else 0)
        transactional_signals = 1 if has_auto else 0

        if category in ("transactional", "billing") and transactional_signals > 0:
            confidence = min(confidence + transactional_signals * 5, 100)
        elif category == "marketing" and marketing_signals > 0:
            confidence = max(confidence - marketing_signals * 5, 0)

        if category in ("transactional", "billing") and marketing_signals > transactional_signals:
            confidence = max(confidence - marketing_signals * 5, 40)
        elif category == "marketing" and transactional_signals > marketing_signals:
            confidence = min(confidence + transactional_signals * 5, 50)

        return category, confidence

    # ----- Vendor enrichment -----

    def _vendor_observations(self, sender: str) -> list[Observation]:
        if not sender:
            return []

        vendor_data = _load_vendor_data()
        domain_index = vendor_data.get("domain_index", {})
        apps = vendor_data.get("apps", {})

        domain = sender.lower().split("@")[-1] if "@" in sender else sender.lower()

        app_id = None
        parts = domain.split(".")
        for i in range(len(parts) - 1):
            candidate = ".".join(parts[i:])
            if candidate in domain_index:
                app_id = domain_index[candidate]
                break

        observations = []
        if app_id and app_id in apps:
            app = apps[app_id]
            observations.append(
                Observation(key="provider", value=app.get("name", ""), type="text")
            )
            observations.append(
                Observation(key="provider_category", value=app.get("category", ""), type="text")
            )
            observations.append(
                Observation(key="provider_org", value=app.get("organization", "unknown"), type="text")
            )

        return observations
