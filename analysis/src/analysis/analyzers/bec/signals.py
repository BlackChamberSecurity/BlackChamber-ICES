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
BEC Analyzer — Content Signal Scanner

Regex-based keyword / entity extraction layer that fires BEFORE NLP.
All signals are computed at zero ML cost.
"""
import re

from analysis.analyzers.bec.models import ContentSignals


# ---------------------------------------------------------------------------
# Keyword lists
# ---------------------------------------------------------------------------

#: Urgency keywords — case-insensitive phrase matching.
_URGENCY_KEYWORDS: list[str] = [
    "urgent", "immediately", "asap", "right away", "time-sensitive",
    "act now", "don't delay", "do not delay", "as soon as possible",
    "right now", "today", "deadline", "critical", "emergency",
    "without delay", "prompt attention", "quickly",
]

#: Payment / financial instruction keywords.
_PAYMENT_KEYWORDS: list[str] = [
    "wire transfer", "ach", "bank account", "routing number",
    "account number", "payment details", "invoice", "direct deposit",
    "bank details", "swift code", "iban", "remittance",
    "payment instructions", "updated banking", "new account",
    "wiring instructions",
]

#: Credential / account access keywords.
_CREDENTIAL_KEYWORDS: list[str] = [
    "password", "login", "verify your account", "credentials",
    "two-factor", "reset your password", "sign in", "authentication",
    "security code", "one-time password", "otp", "mfa",
]

#: Personal information keywords.
_PERSONAL_INFO_KEYWORDS: list[str] = [
    "social security", "ssn", "date of birth", "tax id", "ein",
    "driver's license", "passport number", "maiden name",
    "personal information", "w-2", "w-9", "1099",
]

#: Formal tone markers.
_FORMAL_MARKERS: list[str] = [
    "dear", "sincerely", "regards", "respectfully", "best regards",
    "kind regards", "yours truly", "cordially", "to whom it may concern",
]

#: Informal tone markers.
_INFORMAL_MARKERS: list[str] = [
    "hey", "hi there", "what's up", "yo", "sup", "thanks!",
    "cheers", "lol", "btw", "fyi", "np", "gonna", "wanna",
]

# ---------------------------------------------------------------------------
# Entity extraction regex
# ---------------------------------------------------------------------------

#: Regex for routing numbers (9-digit near financial context).
_ROUTING_RE = re.compile(
    r"(?:routing|aba|transit)[^\d]{0,20}(\d{9})\b", re.IGNORECASE,
)
#: Regex for account numbers (8-17 digits near account context).
_ACCOUNT_RE = re.compile(
    r"(?:account|acct)[^\d]{0,20}(\d{8,17})\b", re.IGNORECASE,
)
#: Regex for bank names (common pattern: "Bank: <Name>").
_BANK_NAME_RE = re.compile(
    r"(?:bank)[:\s]+([A-Z][A-Za-z\s&'.]{2,30})", re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def _count_keyword_hits(text_lower: str, keywords: list[str]) -> int:
    """Count how many distinct keywords appear in the text."""
    return sum(1 for kw in keywords if kw in text_lower)


def _scan_content_signals(text: str) -> ContentSignals:
    """Extract granular content signals from email body text.

    Runs purely on regex / keyword matching — zero ML cost.
    """
    cs = ContentSignals()
    text_lower = text.lower()

    # --- Financial entity extraction ---
    for m in _ROUTING_RE.finditer(text):
        cs.financial_entities.append(f"routing:{m.group(1)}")
    for m in _ACCOUNT_RE.finditer(text):
        cs.financial_entities.append(f"account:{m.group(1)}")
    for m in _BANK_NAME_RE.finditer(text):
        cs.financial_entities.append(f"bank:{m.group(1).strip()}")
    cs.has_financial_entities = len(cs.financial_entities) > 0

    # --- Keyword category flags ---
    urgency_hits = _count_keyword_hits(text_lower, _URGENCY_KEYWORDS)
    payment_hits = _count_keyword_hits(text_lower, _PAYMENT_KEYWORDS)
    cred_hits = _count_keyword_hits(text_lower, _CREDENTIAL_KEYWORDS)
    pii_hits = _count_keyword_hits(text_lower, _PERSONAL_INFO_KEYWORDS)

    cs.has_urgency_language = urgency_hits > 0
    cs.has_payment_instructions = payment_hits > 0
    cs.has_credential_request = cred_hits > 0
    cs.has_personal_info_request = pii_hits > 0

    # Urgency score: density-based, 0-100
    cs.urgency_score = min(100, urgency_hits * 20)

    # --- Formality scoring ---
    formal_hits = _count_keyword_hits(text_lower, _FORMAL_MARKERS)
    informal_hits = _count_keyword_hits(text_lower, _INFORMAL_MARKERS)
    total_tone = formal_hits + informal_hits
    if total_tone > 0:
        cs.formality_score = int((formal_hits / total_tone) * 100)
    else:
        cs.formality_score = 50  # neutral

    return cs
