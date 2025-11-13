"""Unit tests for keyword extraction, explanation formatting, and threat level boundaries.

Covers internal helper methods in UnifiedSearchService to lock in new minimal mode behavior:
- _extract_keyword_matches: stop-word filtering, token overlap, length ≥3
- _build_explanation: inclusion of Keywords= and UrgencySignals= segments
- _determine_threat_level: mapping with NEGLIGIBLE added

These tests intentionally call protected methods for precise validation. If the
public API changes, they can be adapted to assert through higher-level search flows.
"""

from typing import List
import re
import pytest

from query_processing.services.unified_search import UnifiedSearchService
from data_preparation.schemas.email import Email
from shared.enums import ThreatLevel


@pytest.fixture(scope="module")
def service() -> UnifiedSearchService:
    # Use provider=False to avoid any external dependency building for these unit tests
    return UnifiedSearchService(use_provider=False, provider_backfill=False)


# ------------------ Keyword Extraction Tests ------------------


def test_keyword_extraction_basic(service: UnifiedSearchService):
    query = "urgent payment verify account"  # includes stop words removal candidate 'account' (kept) and valid tokens
    target = "Please VERIFY your ACCOUNT now. This is URGENT payment notice."  # Mixed case
    matches = service._extract_keyword_matches(query, target)
    assert set(matches) >= {
        "urgent",
        "payment",
        "verify",
        "account",
    }, f"Expected all query tokens matched. Got {matches}"
    # Ensure uniqueness
    assert len(matches) == len(set(matches))


def test_keyword_extraction_stop_words_filtered(service: UnifiedSearchService):
    query = "the and urgent action to verify"  # includes stop words and valid tokens
    target = "Urgent action required - please verify details"  # Contains valid tokens
    matches = service._extract_keyword_matches(query, target)
    # Stop words should not appear
    assert "the" not in matches and "and" not in matches and "to" not in matches
    # Valid tokens present
    assert set(matches) >= {"urgent", "action", "verify"}


def test_keyword_extraction_min_length(service: UnifiedSearchService):
    query = "id ok urgent pay"  # 'id' and 'ok' are <3 chars so should be ignored, 'pay' passes length but may not match fully
    target = "An urgent payment request needs review"  # Contains 'urgent' and 'payment'
    matches = service._extract_keyword_matches(query, target)
    assert "id" not in matches and "ok" not in matches, "Short tokens should be excluded"
    assert "urgent" in matches
    # 'pay' does not appear standalone; ensure partial substrings not falsely matched
    assert "pay" not in matches


# ------------------ Explanation Formatting Tests ------------------


def build_mock_email(subject: str, body: str, phishing: bool = False) -> Email:
    return Email(
        id="email_1",
        sender="sender@example.com",
        recipient="victim@example.com",
        subject=subject,
        body=body,
        timestamp="2024-01-01T00:00:00Z",
        category="phishing" if phishing else "legitimate",
        is_phishing=phishing,
        confidence_score=0.0,
    )


def test_explanation_contains_keywords_and_urgency(service: UnifiedSearchService):
    email = build_mock_email(
        subject="URGENT payment verification required",
        body="Please verify your account immediately or access will suspend.",
        phishing=True,
    )
    keywords = ["urgent", "payment", "verify", "account"]
    explanation = service._build_explanation(0.85, keywords, 0.72, ThreatLevel.MEDIUM, email)
    # Keywords segment
    assert "Keywords=" in explanation
    for kw in keywords:
        assert kw in explanation, f"Keyword '{kw}' missing from explanation"
    # Urgency signals (urgent, verify, suspend)
    assert "UrgencySignals=" in explanation, "UrgencySignals segment missing"
    assert (
        "Label=PhishingSample" in explanation
    ), "Phishing label should be present for is_phishing=True"


def test_explanation_absence_when_no_keywords_or_urgency(service: UnifiedSearchService):
    email = build_mock_email(
        subject="Quarterly newsletter",
        body="Welcome to our regular company update.",
        phishing=False,
    )
    keywords: List[str] = []
    explanation = service._build_explanation(0.22, keywords, 0.18, ThreatLevel.NEGLIGIBLE, email)
    assert "Keywords=" not in explanation
    assert "UrgencySignals=" not in explanation
    assert "Label=PhishingSample" not in explanation


# ------------------ Threat Level Boundary Tests ------------------


def test_threat_level_boundaries(service: UnifiedSearchService):
    # Explicit boundary checks
    assert service._determine_threat_level(0.81) == ThreatLevel.CRITICAL
    assert service._determine_threat_level(0.8) == ThreatLevel.CRITICAL
    assert service._determine_threat_level(0.79) == ThreatLevel.HIGH
    assert service._determine_threat_level(0.61) == ThreatLevel.HIGH
    assert service._determine_threat_level(0.6) == ThreatLevel.HIGH
    assert service._determine_threat_level(0.59) == ThreatLevel.MEDIUM
    assert service._determine_threat_level(0.41) == ThreatLevel.MEDIUM
    assert service._determine_threat_level(0.4) == ThreatLevel.MEDIUM
    assert service._determine_threat_level(0.39) == ThreatLevel.LOW
    assert service._determine_threat_level(0.21) == ThreatLevel.LOW
    assert service._determine_threat_level(0.2) == ThreatLevel.LOW
    assert service._determine_threat_level(0.19) == ThreatLevel.NEGLIGIBLE
    assert service._determine_threat_level(0.0) == ThreatLevel.NEGLIGIBLE


def test_threat_level_negligible_label(service: UnifiedSearchService):
    email = build_mock_email("Status update", "Just a normal update.")
    explanation = service._build_explanation(0.05, [], 0.07, ThreatLevel.NEGLIGIBLE, email)
    # Normalize and check lowercase key/value pattern
    assert "level=negligible" in explanation.lower(), "Explanation should reflect negligible level"


# ------------------ Robustness / Edge Cases ------------------


def test_keyword_extraction_empty_query(service: UnifiedSearchService):
    matches = service._extract_keyword_matches("", "Some text")
    assert matches == []


def test_keyword_extraction_no_overlap(service: UnifiedSearchService):
    matches = service._extract_keyword_matches("bitcoin wallet seed", "Quarterly financial report")
    assert matches == []


def test_explanation_format_basic_structure(service: UnifiedSearchService):
    email = build_mock_email("Notice", "Routine maintenance tomorrow.")
    explanation = service._build_explanation(0.55, [], 0.33, ThreatLevel.LOW, email)
    # Basic parts present
    assert re.search(r"Similarity=\d+\.\d{3}", explanation)
    assert "ThreatScore=" in explanation
    assert "Level=" in explanation
