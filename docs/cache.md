# Caching Strategy

## 1. Purpose
Caching reduces repeat computation costs (embeddings, feature extraction, full pipeline results) to keep interactive threat hunting fast.

## 2. Cache Types
| Type | Location / Path | Persistence | Scope | Contents |
|------|-----------------|------------|-------|----------|
| Embedding Cache | `src/shared/cache/embeddings_cache/` | Disk | Global | Stored embedding vectors / derived artifacts (if implemented) |
| Query Results Cache | In-memory (see `QueryResultsCache`) | Memory (TTL eviction) | Global process | Serialized pipeline output per normalized query key |
| Feature Cache (Urgency, Attachments, etc.) | `cache/application/threat_features/` | Disk (optional) | Application | Precomputed feature results per email |
| Domain Analysis Cache | `cache/application/domain_analysis/` | Disk | Application | New sender / domain novelty signals |
| Similarity Cache | `cache/application/similarity_scores/` | Disk | Application | Cached similarity computations / normalization helpers |
| Model Cache | `src/shared/cache/models_cache/` | Disk | Global | Downloaded transformer model weights |
| Session Store | `cache/temp/user_sessions/` or Redis | Memory/disk | Per session | Chat turns for `/api/v1/chat` refinement |
| Temp Cache | `cache/temp/` | Disk | Ephemeral | Short-lived intermediate artifacts |

## 3. QueryResultsCache Details
Implemented in `src/shared/cache/query_cache.py`.

Features:
- TTL-based expiration (default ~1h from config).
- LRU eviction when `max_size` exceeded.
- Key normalization includes query text, search method, threshold, limit, explanation mode.
- Stores lightweight serialized structures (not entire email bodies duplicated).

Miss → pipeline runs; Hit → fast path (deserialize) reducing latency.

## 4. Invalidation & Freshness
| Cache | Invalidation Trigger |
|-------|----------------------|
| Embedding | Rebuild index (`make rebuild-index` / dataset change) |
| Query Results | TTL expiry or key mismatch (different params) |
| Feature / Similarity | Manual cleanup (`make full-reset` or `clean_repo.sh`) or new dataset generation |
| Domain Analysis | Same as feature cache; domain changes cause recompute on next access |
| Session Store | Explicit new session or TTL expiration (if Redis configured) |

## 5. Configuration Toggles (from `Config`)
| Setting | Effect |
|---------|-------|
| `enable_query_cache` | Disable/enable QueryResultsCache usage |
| `enable_embedding_cache` | Control disk embedding reuse logic |
| `max_cache_size` | Cap for in-memory query cache entries |
| `cache_ttl_seconds` | Time-to-live for query result entries |
| `redis_enabled` + `redis_url` | Switch session store to Redis backend |

## 6. Key Design Choices
- Separation between infrastructure caches (persistent embeddings/models) and application caches (feature & similarity) keeps cleanup safe.
- QueryResultsCache intentionally ignores ephemeral parameters (like timestamps) to increase hit probability.
- Disk-based feature caches accelerate large repeated batch analyses or interactive refinement across same candidate set.

## 7. Risks & Mitigations
| Risk | Impact | Mitigation |
|------|--------|-----------|
| Stale feature data after model logic change | Inaccurate scores | Run `make full-reset` to purge caches |
| Memory growth from large query variety | High RAM usage | LRU eviction + max size limit |
| Redis outage | Lost chat continuity | Automatic fallback to memory SessionStore |
| Cache corruption (disk) | Exceptions on read | Graceful exception handling & rebuild next access |

## 8. Operational Tasks
| Task | Command |
|------|---------|
| Clear all caches + index | `make full-reset` |
| Clear only logs/temp | `make clean` |
| Rebuild index (keep dataset) | `make rebuild-index` |

## 9. Extending Caches
To add a new cache:
1. Define directory under `cache/application/` or reuse memory-only structure.
2. Add path to `Config` for visibility.
3. Implement get/set wrapper with TTL if needed.
4. Add tests covering hit/miss/eviction.

## 10. Future Improvements
| Idea | Benefit |
|------|--------|
| Redis-backed query cache | Horizontal scaling for API nodes |
| Adaptive TTL (based on query frequency) | Keeps popular queries hot longer |
| Bloom filter for quick negative checks | Reduce hash lookups for unlikely repeats |
| Metrics integration (prometheus) | Visibility into hit ratio / eviction count |

---
Caching accelerates analyst workflows—periodically verify freshness and purge when logic/weights change.
