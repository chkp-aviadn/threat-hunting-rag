"""Tests exact natural language query strings from specification.

Queries:
1. "Show me emails with urgent payment requests from new senders"
2. "Find emails with suspicious attachment names"
3. "Identify emails that impersonate executives"

Validations:
- Each query processes successfully (processing_time_ms recorded)
- Hybrid search returns >=0 results (non-crashing)
- At least one result across all queries contains explanation with expected keyword tokens
- Keyword extraction picks up core intent words (urgent/payment, suspicious/attachment, impersonate/executives)
Resilient: Does not fail if a single query yields zero results; aggregates hits.
"""

import sys, pathlib

root = pathlib.Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(root))

from query_processing.services.unified_search import UnifiedSearchService
from query_processing.models.search import SearchQuery
from shared.enums import SearchMethod

SPEC_QUERIES = [
    "Show me emails with urgent payment requests from new senders",
    "Find emails with suspicious attachment names",
    "Identify emails that impersonate executives",
]

CORE_TOKENS = {
    "urgent": {"urgent", "payment", "requests"},
    "suspicious": {"suspicious", "attachment", "names"},
    "impersonate": {"impersonate", "executives"},
}


def test_spec_queries_process_and_keywords():
    service = UnifiedSearchService(use_provider=False, provider_backfill=False)
    assert service.ensure_index_ready()
    keyword_hits = 0
    explanations_with_tokens = 0

    for q in SPEC_QUERIES:
        results = service.search(SearchQuery(text=q, method=SearchMethod.HYBRID, limit=8))
        assert results.processing_time_ms >= 0, "Processing time missing"
        # Derive expectation group key
        group_key = (
            "urgent" if "urgent" in q else ("suspicious" if "suspicious" in q else "impersonate")
        )
        expected_tokens = CORE_TOKENS[group_key]
        # Scan results for token presence in keyword_matches or explanation
        for r in results.results:
            expl_lower = (r.explanation or "").lower()
            km_lower = {k.lower() for k in (r.keyword_matches or [])}
            if km_lower.intersection(expected_tokens):
                keyword_hits += 1
            if any(t in expl_lower for t in expected_tokens):
                explanations_with_tokens += 1

    # Require at least some keyword extraction hits across all queries
    assert keyword_hits >= 1, "No keyword matches detected for spec queries"
    # Require explanations surface tokens
    assert explanations_with_tokens >= 2, "Insufficient explanations containing expected tokens"
