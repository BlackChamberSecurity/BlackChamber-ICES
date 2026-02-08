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
Analyzer: SaaS Usage Classification

NLP-first architecture:
  1. Header signals — structured metadata NLP can't see (List-Unsubscribe, etc.)
  2. NLP classification — zero-shot transformer classifies email type
  3. Vendor enrichment — match sender domain against known vendor dataset

Score interpretation:
    80-100 = Confirmed SaaS usage (billing, OTP, admin alerts)
    40-79  = Likely SaaS usage (account notifications, updates)
    0-39   = Marketing / promotional / noise
"""
import json
import logging
import re
from html.parser import HTMLParser
from pathlib import Path

from analysis.analyzers._base import BaseAnalyzer
from analysis.models import AnalysisResult, EmailEvent

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
        # Fallback: crude regex strip
        text = re.sub(r"<[^>]+>", " ", html)
    # Collapse whitespace
    return re.sub(r"\s+", " ", text).strip()

# ---------------------------------------------------------------------------
# Vendor dataset — loaded once per worker process
# ---------------------------------------------------------------------------
_VENDOR_DATA = None


def _load_vendor_data():
    """Load saas_vendors.json once per worker process."""
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
    """Lazy-load the zero-shot classification pipeline."""
    global _nlp_classifier
    if _nlp_classifier is None:
        try:
            from transformers import pipeline
            logger.info("Loading zero-shot classification model...")
            _nlp_classifier = pipeline(
                "zero-shot-classification",
                model="cross-encoder/nli-distilroberta-base",
                device=-1,  # CPU
            )
            logger.info("NLP model loaded successfully")
        except Exception as exc:
            logger.warning("Failed to load NLP model: %s. Falling back to headers only.", exc)
            _nlp_classifier = False  # sentinel: tried and failed
    return _nlp_classifier if _nlp_classifier is not False else None


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------
class SaaSUsageAnalyzer(BaseAnalyzer):
    """Classify emails as SaaS usage indicators vs marketing noise.

    NLP-first: every email goes through zero-shot classification.
    Header signals provide structured metadata NLP can't see.
    Dataset enrichment attaches vendor metadata post-classification.
    """

    name = "saas_usage"
    description = "Classifies emails as transactional SaaS usage vs marketing noise using NLP, enriched with vendor metadata"
    severity_weight = 100

    def analyze(self, email: EmailEvent) -> AnalysisResult:
        findings = []

        # --- Step 1: Header signals (structured metadata NLP can't see) ---
        header_signals = self._collect_header_signals(email)
        findings.extend(header_signals["findings"])

        # --- Step 2: NLP classification ---
        score, category, nlp_findings = self._nlp_classify(email)
        findings.extend(nlp_findings)

        # --- Step 3: Adjust score based on header signals ---
        score, category = self._adjust_with_headers(
            score, category, header_signals
        )

        result = AnalysisResult(
            analyzer=self.name,
            score=score,
            findings=findings,
            category=category,
        )

        # --- Step 4: Enrich with vendor dataset ---
        result = self._enrich_with_vendor_data(email.sender, result)

        return result

    # ----- Header signal collection -----

    def _collect_header_signals(self, email: EmailEvent) -> dict:
        """Extract signals from email headers that NLP can't see."""
        findings = []
        headers = email.headers

        marketing_signals = 0
        transactional_signals = 0

        # List-Unsubscribe is a strong marketing/bulk indicator
        if headers.get("List-Unsubscribe"):
            marketing_signals += 2
            findings.append("Header: List-Unsubscribe present (marketing indicator)")

        # Precedence: bulk/list = mass mailing
        precedence = headers.get("Precedence", "").lower()
        if precedence in ("bulk", "list"):
            marketing_signals += 2
            findings.append(f"Header: Precedence={precedence} (bulk mail)")

        # Auto-Submitted = automated/transactional
        auto_submitted = headers.get("Auto-Submitted", "").lower()
        if auto_submitted and auto_submitted != "no":
            transactional_signals += 2
            findings.append("Header: Auto-Submitted (automated/transactional)")

        # X-Mailer from known marketing platforms
        x_mailer = headers.get("X-Mailer", "").lower()
        marketing_mailers = [
            "mailchimp", "sendgrid", "marketo", "hubspot",
            "pardot", "constant contact",
        ]
        for mailer in marketing_mailers:
            if mailer in x_mailer:
                marketing_signals += 1
                findings.append(f"Header: X-Mailer={mailer} (marketing platform)")
                break

        return {
            "transactional": transactional_signals,
            "marketing": marketing_signals,
            "findings": findings,
        }

    # ----- NLP classification -----

    def _nlp_classify(
        self, email: EmailEvent
    ) -> tuple[int, str, list[str]]:
        """Classify the email using zero-shot NLP with binary labels."""
        findings = []

        classifier = _get_nlp_classifier()
        if classifier is None:
            findings.append("NLP unavailable — no classification")
            return 0, "unknown", findings

        # Build text to classify: subject + body (stripped of HTML)
        body_text = email.body.content or ""
        if email.body.content_type == "html" or "<" in body_text[:50]:
            body_text = _strip_html(body_text)

        text = f"Subject: {email.subject or '(no subject)'}\n\n"
        text += body_text[:500]

        # Binary labels — clean contrastive signal for NLI
        candidate_labels = [
            "automated notification from a software application",
            "marketing newsletter or promotional content",
        ]

        try:
            result = classifier(text, candidate_labels, multi_label=False)
            top_label = result["labels"][0]
            top_score = result["scores"][0]

            findings.append(
                f"NLP: '{top_label}' (confidence: {top_score:.2f})"
            )

            if "notification" in top_label:
                category = "transactional"
                score = int(top_score * 100)
            else:
                category = "marketing"
                score = int(top_score * 100)

            return score, category, findings

        except Exception as exc:
            logger.warning("NLP classification failed: %s", exc)
            findings.append(f"NLP error: {exc}")
            return 0, "unknown", findings

    # ----- Score adjustment -----

    def _adjust_with_headers(
        self, score: int, category: str, header_signals: dict
    ) -> tuple[int, str]:
        """Adjust NLP score using header signals that the model can't see."""
        t = header_signals["transactional"]
        m = header_signals["marketing"]

        # Headers reinforce NLP when they agree
        if category in ("transactional", "billing") and t > 0:
            score = min(score + t * 5, 100)
        elif category == "marketing" and m > 0:
            score = max(score - m * 5, 0)

        # Headers contradict NLP — moderate the score toward neutral
        if category in ("transactional", "billing") and m > t:
            score = max(score - m * 5, 40)
        elif category == "marketing" and t > m:
            score = min(score + t * 5, 50)

        return score, category

    # ----- Vendor dataset enrichment -----

    def _enrich_with_vendor_data(
        self, sender: str, result: AnalysisResult
    ) -> AnalysisResult:
        """Enrich the result with vendor metadata from the known dataset.

        Post-classification only — doesn't affect the score, just adds
        structured metadata (provider name, category) when the sender
        domain matches a known SaaS application.
        """
        if not sender:
            return result

        vendor_data = _load_vendor_data()
        domain_index = vendor_data.get("domain_index", {})
        apps = vendor_data.get("apps", {})

        # Extract domain from sender
        domain = sender.lower().split("@")[-1] if "@" in sender else sender.lower()

        # Walk up subdomains: notifications.github.com → github.com
        app_id = None
        parts = domain.split(".")
        for i in range(len(parts) - 1):
            candidate = ".".join(parts[i:])
            if candidate in domain_index:
                app_id = domain_index[candidate]
                break

        if app_id and app_id in apps:
            app = apps[app_id]
            result.provider = app.get("name", "")
            if result.category in ("unknown", ""):
                result.category = app.get("category", "")
            result.findings.append(
                f"Vendor: {app.get('name', '')} ({app.get('category', '')}) "
                f"[org: {app.get('organization', 'unknown')}]"
            )

        return result
