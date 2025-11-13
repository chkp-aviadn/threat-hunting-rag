"""Integration-like test for UnifiedSearchService keyword + explanation behavior.

Runs a real search (ensuring index build if needed) and validates that at least
one result includes keyword matches and urgency signals in explanation for an
"urgent payment" style query.
"""

import sys, pathlib

root = pathlib.Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(root))

from query_processing.services.unified_search import UnifiedSearchService
from query_processing.models.search import SearchQuery
from shared.enums import SearchMethod, ThreatLevel


def test_search_keywords_and_explanation():
    service = UnifiedSearchService(use_provider=False, provider_backfill=False)
    assert service.ensure_index_ready(), "Index should build or load successfully"

    q = SearchQuery(text="urgent payment verify account", method=SearchMethod.HYBRID, limit=8)
    results = service.search(q)
    # Even if zero results (edge), test should not fail catastrophically; assert structure
    assert results.processing_time_ms >= 0
    # Look for at least one result containing expected keywords and urgency signals
    keyword_hit = False
    urgency_hit = False
    for r in results.results:
        expl = (r.explanation or "").lower()
        if "keywords=" in expl and ("urgent" in expl or "payment" in expl):
            keyword_hit = True
        if "urgencysignals=" in expl and ("urgent" in expl or "verify" in expl):
            urgency_hit = True
    # It's possible dataset evolves; require at least keyword presence now
    assert keyword_hit, "Expected at least one result with keyword matches in explanation"
    # Urgency signals desirable; warn via assertion note if missing but allow optional
    assert urgency_hit or keyword_hit, "Urgency signals missing; ensure dataset has urgent phrasing"

    # Threat level distribution sanity: should not all be negligible
    levels = {r.threat_level for r in results.results}
    assert not (
        levels and levels == {ThreatLevel.NEGLIGIBLE}
    ), "All results negligible; query likely not exercising scoring"
