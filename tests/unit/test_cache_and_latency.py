"""Tests for cache behavior and latency expectations."""

import time
import sys, pathlib

root = pathlib.Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(root))

from query_processing.services.unified_search import UnifiedSearchService
from query_processing.models.search import SearchQuery
from shared.enums import SearchMethod


def test_query_cache_hit_and_stats():
    service = UnifiedSearchService(use_provider=False, provider_backfill=False)
    assert service.ensure_index_ready()
    q = SearchQuery(text="urgent payment", method=SearchMethod.HYBRID, limit=6)
    first = service.search(q)
    stats_after_first = service.get_query_cache_stats()
    second = service.search(q)  # Should hit cache
    stats_after_second = service.get_query_cache_stats()
    assert stats_after_first.get("hits", 0) <= stats_after_second.get(
        "hits", 0
    ), "Cache hits did not increase"
    assert (
        stats_after_second.get("last_cache_hit") is True
    ), "Cache hit flag not set after repeat query"


def test_warm_search_latency_reasonable():
    service = UnifiedSearchService(use_provider=False, provider_backfill=False)
    assert service.ensure_index_ready()
    # Warm-up query (loads model/embeddings) may be slower; ignore
    _ = service.search(SearchQuery(text="warm up", method=SearchMethod.HYBRID, limit=4))
    t0 = time.time()
    res = service.search(
        SearchQuery(text="verify account access", method=SearchMethod.HYBRID, limit=6)
    )
    elapsed_ms = (time.time() - t0) * 1000
    assert elapsed_ms < 1500, f"Warm search latency too high: {elapsed_ms:.1f}ms"
    assert res.processing_time_ms <= elapsed_ms + 50  # internal timing near wall clock
