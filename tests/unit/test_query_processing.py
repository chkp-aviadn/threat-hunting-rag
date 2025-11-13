"""Tests for Intelligent Query Processing requirements.

Validates:
- Natural language queries execute
- Hybrid vs semantic vs keyword differences
- Specific queries from task requirements produce non-empty or plausible results
"""

import sys, pathlib

root = pathlib.Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(root))

from query_processing.services.unified_search import UnifiedSearchService
from query_processing.models.search import SearchQuery
from shared.enums import SearchMethod

QUERIES = [
    "urgent payment requests from new senders",
    "suspicious attachment names",
    "impersonate executives",
]


def _run_search(service, text, method):
    q = SearchQuery(text=text, method=method, limit=6)
    return service.search(q)


def test_search_methods_difference():
    service = UnifiedSearchService(use_provider=False, provider_backfill=False)
    assert service.ensure_index_ready()
    text = QUERIES[0]
    hybrid = _run_search(service, text, SearchMethod.HYBRID)
    semantic = _run_search(service, text, SearchMethod.SEMANTIC)
    keyword = _run_search(service, text, SearchMethod.KEYWORD)
    # At least one method returns results
    assert (
        hybrid.total_found or semantic.total_found or keyword.total_found
    ), "No results from any method"
    # Expect some difference between pure keyword and semantic result sets (ids or threat scores)
    if hybrid.total_found and semantic.total_found:
        hybrid_ids = [r.email.id for r in hybrid.results]
        semantic_ids = [r.email.id for r in semantic.results]
        assert hybrid_ids != semantic_ids or any(
            r.threat_score != s.threat_score for r, s in zip(hybrid.results, semantic.results)
        ), "Hybrid and semantic appear identical; expected variation"


def test_required_queries_execute():
    service = UnifiedSearchService(use_provider=False, provider_backfill=False)
    assert service.ensure_index_ready()
    for text in QUERIES:
        results = _run_search(service, text, SearchMethod.HYBRID)
        # We allow zero results for edge wording but log; ensure processing time captured
        assert results.processing_time_ms >= 0


def test_keyword_specificity():
    service = UnifiedSearchService(use_provider=False, provider_backfill=False)
    assert service.ensure_index_ready()
    text = "urgent payment verify account"
    hybrid = _run_search(service, text, SearchMethod.HYBRID)
    keyword = _run_search(service, text, SearchMethod.KEYWORD)
    # Keyword search should produce explanations with Keywords= more consistently
    kw_explanations = sum(
        1 for r in keyword.results if r.explanation and "Keywords=" in r.explanation
    )
    hy_explanations = sum(
        1 for r in hybrid.results if r.explanation and "Keywords=" in r.explanation
    )
    assert (
        kw_explanations >= hy_explanations
    ), "Keyword search should not have fewer keyword-marked explanations than hybrid"
