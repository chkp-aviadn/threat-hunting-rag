# Performance Guide

## 1. Goals
Maintain responsive threat hunting (sub‑second typical interactive queries after warm-up) while keeping resource usage modest.

## 2. Latency Breakdown (Single Query)
| Stage | Typical Cost | Notes |
|-------|--------------|------|
| Embedding model warm-up | 1–3 s (first use) | One-time load; subsequent queries faster |
| Semantic + keyword retrieval | ~50–150 ms | Chroma vector search + keyword filtering |
| Feature extraction per email | ~1–5 ms each | Regex / heuristic operations, linear in result count |
| Scoring + explanation | ~1–3 ms each | Simple arithmetic / string assembly |
| Threshold filtering | Negligible | In-memory list comprehension |
| Caching check (query) | 0.1–1 ms | Hash + dictionary access |

Total (warm): usually < 300 ms for 10 results.

## 3. Warm-Up Strategy
Run one broad query after startup (e.g. "urgent payment") to load model + index into memory and prime Python modules.

## 4. Caching Impact
- QueryResultsCache: Avoids full retrieval & feature pass for identical queries (potential latency drop to < 20 ms).
- Feature & similarity caches: Reduce repeated extraction cost when same emails appear across related queries.
- Embedding cache (persisted): Rebuilding index skips recomputation for unchanged items.

## 5. Index Rebuild Cost
| Operation | Approximate Duration |
|-----------|----------------------|
| Dataset generation (150 synthetic emails) | < 2 s |
| Embedding computation (MiniLM) | ~3–5 s (cold) |
| Chroma persist commit | < 1 s |
| Total rebuild (`make rebuild-index`) | ~5–8 s |

## 6. Scaling Considerations
| Axis | Challenge | Approach |
|------|----------|----------|
| Volume (10k+ emails) | Feature pass becomes larger | Batch extraction, async / multiprocessing |
| Concurrency (many API users) | Shared model contention | Model pool / shared server process w/ gunicorn workers |
| Memory footprint | Large embeddings set | Use disk-backed vector DB + on-demand loading |
| High query rate | Cache churn & CPU usage | Increase cache size / introduce Redis LRU |

## 7. Optimization Levers
| Lever | Effect |
|-------|--------|
| Reduce max_results | Less feature extraction cost |
| Enable query cache | Instant repeat query responses |
| Pre-warm embeddings | Lowers first query latency |
| Async extraction (future) | Overlap IO / processing |
| Lightweight similarity normalization | Avoid heavy transforms |

## 8. Monitoring Suggestions
| Metric | Reason |
|--------|--------|
| p95 query latency | User experience baseline |
| Cache hit ratio | Efficiency of repeated queries |
| Embedding rebuild time | Operational maintenance cost |
| Memory usage | Detect leaks / oversizing |
| Error rate | Stability tracking |

## 9. Benchmark Script
Use `scripts/benchmark_search.py` (if present) or create one that runs a battery of representative queries logging timings.

## 10. Future Improvements
| Idea | Benefit |
|------|--------|
| Vector pruning by recency | Smaller search space |
| Approximate nearest neighbor tuning | Faster semantic retrieval |
| Adaptive caching TTL | Balance freshness vs performance |
| Parallel feature extraction | Speed with multiprocess concurrency |

---
Keep performance tuning iterative: profile before optimizing; measure after changes; avoid premature complexity.
