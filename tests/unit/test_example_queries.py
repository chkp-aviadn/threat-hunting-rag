"""Runs at least 10 example queries to demonstrate system capabilities.

Each query asserts basic invariants: processing time recorded, results object structure.
Does not enforce non-empty results for every query (some may be intentionally sparse)
but ensures overall query diversity returns at least some hits.
"""

import sys, pathlib

root = pathlib.Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(root))

from query_processing.services.unified_search import UnifiedSearchService
from query_processing.models.search import SearchQuery
from shared.enums import SearchMethod

EXAMPLE_QUERIES = [
    "urgent payment request",
    "wire transfer invoice",
    "verify account access",
    "suspicious attachment name",
    "impersonate executive",
    "login credential harvest",
    "reset password immediately",
    "invoice overdue notice",
    "financial department update",
    "payment confirmation required",
    "suspend account action required",
]


def test_run_example_queries():
    service = UnifiedSearchService(use_provider=False, provider_backfill=False)
    assert service.ensure_index_ready()
    non_empty = 0
    for q in EXAMPLE_QUERIES:
        res = service.search(SearchQuery(text=q, method=SearchMethod.HYBRID, limit=6))
        assert res.processing_time_ms >= 0
        assert isinstance(res.total_found, int)
        if res.total_found > 0:
            non_empty += 1
    # Ensure at least half produced hits (dataset relevance sanity)
    assert non_empty >= len(EXAMPLE_QUERIES) // 2, f"Too few queries returned results ({non_empty})"
