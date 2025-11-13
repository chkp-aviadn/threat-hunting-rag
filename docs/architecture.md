# Architecture Overview

## 1. High-Level Concept
The system provides phishing threat hunting over a synthetic email dataset using hybrid retrieval (semantic + keyword) plus feature-based risk scoring and human-readable explanations. It exposes both a CLI (single & interactive queries) and a REST API (search, refine, chat).

## 2. Core Components
| Layer | Module / Path | Responsibility |
|-------|---------------|----------------|
| Data | `data/emails.csv`, `data/chroma/` | Persistent email corpus & Chroma vector index |
| Retrieval | `src/query_processing/services/unified_search.py` | Hybrid search (semantic embeddings + keyword matching + fallback) |
| Threat Feature Extraction | `src/threat_analysis/detection/features.py` | Extract urgency, impersonation, suspicious attachment, financial/credential signals |
| Scoring | `src/threat_analysis/detection/scorer.py` | Combine feature confidences, similarity, boosts to produce `threat_score` + level |
| Orchestration | `src/orchestration/rag_pipeline.py` | Drives end-to-end query: retrieval → enhancement → scoring → explanation formatting |
| Explanation | `src/threat_analysis/reasoning/explainer.py` | Generates detailed narrative & indicator grouping |
| Interfaces | `src/interfaces/cli/app.py`, `src/interfaces/api/app.py` | CLI commands, API endpoints (search/refine/chat/health) |
| Configuration | `src/shared/config.py` | Central config (paths, cache toggles, tuning knobs) |
| Caching | `src/shared/cache/query_cache.py` (+ dirs under `cache/`) | Query results caching (TTL + LRU) and application-level feature/similarity caches |
| Sessions | `src/shared/session_store.py` | Chat session persistence (memory or Redis) |

## 3. Data Flow (Single Query)
1. User issues query (CLI or API) with optional threshold & parameters.
2. Pipeline requests hybrid search results (semantic vectors from Chroma + keyword scoring).
3. Raw matches converted to pipeline results; feature extractor analyzes each email.
4. Scorer blends similarity & feature confidences to compute `threat_score` + level.
5. Explanation builder compiles overview, indicators, risk summary, recommended action (and optional detailed section).
6. Results filtered by threshold, limited, returned (optionally cached).

```
[Query] -> [UnifiedSearchService] -> results -> [FeatureExtractor] -> features
       -> [ThreatScorer] -> threat_score -> [ExplanationBuilder] -> explanation
       -> [Threshold Filter] -> final list -> [Output Formatter]
```

## 4. Refinement Flow
Refinement (CLI `refine`, API `/search/refine`, chat refine) reuses prior retrieved set:
- Apply new threshold / focus filters locally.
- No new embedding or DB calls → faster triage.

## 5. Chat Flow
1. User message sent to `/api/v1/chat` with session_id (or new session).
2. If `refine=true`, filter previous session results; else perform fresh pipeline query.
3. Append turn to `SessionStore`.
4. Return results + optional suggestions.

## 6. Threat Score Composition (Concept)
Score combines:
- Base similarity (normalized raw embedding similarity).
- Weighted feature confidences (urgency, impersonation, suspicious attachment, new sender + derived financial/credential/link signals).
- Minor keyword boost.
- Final mapped to level thresholds (LOW/MEDIUM/HIGH/CRITICAL).
(Details in `docs/scoring.md`).

## 7. Caching Strategy (Overview)
- QueryResultsCache: avoids recomputing entire pipeline for identical parameters (TTL + LRU).
- Feature / similarity caches: store intermediate computations per email to speed repeated analyses.
- Embedding/model caches: avoid re-downloading models & recomputing embeddings (persist on disk).
(Details in `docs/cache.md`).

## 8. Error / Resilience Measures
| Concern | Strategy |
|---------|----------|
| Missing dataset | `--setup` / bootstrap regenerate script |
| Empty filtered results | Fallback: return unfiltered enhanced set (prevents 0-result frustrations) |
| Explainer failure | Graceful fallback to minimal format |
| Cache exceptions | Logged debug; pipeline continues |
| Redis unavailable | Session store falls back to in-memory |

## 9. Extensibility Points
- Add new detection features (extend `FeatureExtractor` + scoring weights).
- Plug alternative vector DB (encapsulated behind search service).
- Swap embedding model via config env vars.
- Add advanced reasoning model to explanation step.

## 10. Future Enhancements
| Area | Potential Improvement |
|------|-----------------------|
| Ranking | Rerank via lightweight ML model |
| Explanations | Include structured JSON (already supported) in all interfaces by default |
| Multi-Tenancy | Namespace datasets & indexes per tenant |
| Security | Role-based API keys, audit log enrichment |
| Performance | Async batch feature extraction, precomputed embeddings warm pool |

## 11. Diagram Reference
See `diagrams/architecture.mmd` for Mermaid-based architecture diagram (can be rendered with `mmdc` or VS Code Mermaid preview).

---
This document is a concise introduction—deeper details live in sibling docs (`scoring.md`, `cache.md`, `performance.md`).
