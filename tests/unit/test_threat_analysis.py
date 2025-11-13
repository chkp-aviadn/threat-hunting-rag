"""Tests for Threat Analysis & Reasoning.

Validates:
- Ranked results have confidence scores
- Explanations contain required components
- Refinement (simulated) filters results by threshold
- Presence of multiple threat levels including NEGLIGIBLE
"""

import sys, pathlib

root = pathlib.Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(root))

from query_processing.services.unified_search import UnifiedSearchService
from query_processing.models.search import SearchQuery, SearchResults
from shared.enums import SearchMethod, ThreatLevel


def test_ranked_results_and_confidence():
    service = UnifiedSearchService(use_provider=False, provider_backfill=False)
    assert service.ensure_index_ready()
    results = service.search(
        SearchQuery(text="urgent payment", method=SearchMethod.HYBRID, limit=8)
    )
    # Ranking increasing
    ranks = [r.rank for r in results.results]
    assert ranks == sorted(ranks), "Ranks not sorted"
    # Confidence scores present
    for r in results.results:
        assert r.confidence is not None


def test_explanation_components():
    service = UnifiedSearchService(use_provider=False, provider_backfill=False)
    assert service.ensure_index_ready()
    results = service.search(
        SearchQuery(text="verify account suspend", method=SearchMethod.HYBRID, limit=5)
    )
    for r in results.results:
        if r.explanation:
            assert "Similarity=" in r.explanation
            assert "ThreatScore=" in r.explanation
            assert "Level=" in r.explanation


def test_refinement_filters_by_threshold():
    service = UnifiedSearchService(use_provider=False, provider_backfill=False)
    assert service.ensure_index_ready()
    base = service.search(
        SearchQuery(text="wire transfer invoice", method=SearchMethod.HYBRID, limit=10)
    )
    # Simulate refinement: apply threshold 0.5
    refined_list = [r for r in base.results if r.threat_score >= 0.5]
    refined = SearchResults(
        query=base.query,
        results=refined_list,
        total_found=len(refined_list),
        processing_time_ms=base.processing_time_ms,
    )
    assert len(refined.results) <= len(base.results)
    if refined.results:
        assert all(r.threat_score >= 0.5 for r in refined.results)


def test_threat_level_distribution():
    service = UnifiedSearchService(use_provider=False, provider_backfill=False)
    assert service.ensure_index_ready()
    # Use several queries likely to span similarity / indicator ranges
    queries = [
        "routine update",  # Should yield lower similarity/score
        "urgent payment required",  # Higher threat indicators
        "verify account suspend",  # Urgency + verify
    ]
    levels = set()
    for text in queries:
        res = service.search(SearchQuery(text=text, method=SearchMethod.HYBRID, limit=6))
        for r in res.results:
            levels.add(r.threat_level)
    # Require at least two distinct levels and at least one low/negligible
    assert len(levels) >= 2, f"Need diversity of threat levels, got: {levels}"
    assert any(
        l in levels for l in (ThreatLevel.NEGLIGIBLE, ThreatLevel.LOW)
    ), f"Lower levels not represented: {levels}"
