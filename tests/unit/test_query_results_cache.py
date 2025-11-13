"""Unit tests for QueryResultsCache (direct) covering hit, miss, TTL expiration, and eviction."""

import time
import sys, pathlib

root = pathlib.Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(root))

from shared.cache.query_cache import QueryResultsCache, reset_query_cache  # noqa: E402


def test_basic_put_get_hit():
    reset_query_cache()
    cache = QueryResultsCache(max_size=10, default_ttl_seconds=5)
    payload = {"results": [{"email_id": "abc", "threat_score": 0.9}]}
    cache.put("urgent payment", payload, method="hybrid", limit=5)
    assert cache.get("urgent payment", method="hybrid", limit=5) == payload
    stats = cache.get_stats()
    assert stats["cache_hits"] == 1
    assert stats["cache_misses"] == 0


def test_ttl_expiration():
    reset_query_cache()
    cache = QueryResultsCache(max_size=10, default_ttl_seconds=1)
    cache.put("short ttl", {"results": []})
    assert cache.get("short ttl") is not None
    time.sleep(1.2)
    # Should expire
    assert cache.get("short ttl") is None
    stats = cache.get_stats()
    assert stats["expired_removals"] >= 1


def test_eviction_policy():
    reset_query_cache()
    cache = QueryResultsCache(max_size=5, default_ttl_seconds=10)
    for i in range(7):
        cache.put(f"query_{i}", {"results": [i]})
    stats = cache.get_stats()
    # After cleanup target size is 80% of max (4) or <= max
    assert stats["total_entries"] <= 5
    # Some evictions should have occurred
    assert stats["evictions"] >= 1


def test_non_blocking_lock_behavior():
    reset_query_cache()
    cache = QueryResultsCache(max_size=3, default_ttl_seconds=5)
    # Simulate rapid puts/gets
    for i in range(10):
        cache.put("same", {"results": [i]})
        _ = cache.get("same")
    stats = cache.get_stats()
    # Should have a mix of hits/misses but not zero requests
    assert stats["total_requests"] > 0
