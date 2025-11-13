# Test Suite Overview

This directory contains automated tests validating the Threat Hunting RAG system.
It is organized by scope:

## Structure
```
tests/
├── unit/        # Fast, isolated tests for individual modules & logic
├── cli/         # Direct invocation of CLI components (no subprocess overhead)
├── e2e/         # End‑to‑end API tests (FastAPI routes & integration wiring)
└── conftest.py  # Shared fixtures (temporary paths, sample data, helpers)
```

## Goals
1. Verify core functionality (data prep, indexing, searching, scoring, explanations).
2. Ensure user interfaces (CLI & API) behave as documented.
3. Keep performance reasonable (no single unit test should exceed a few seconds).
4. Provide confidence that refactors won’t silently break the threat hunting pipeline.

## Categories

### Unit Tests (`tests/unit/`)
| File | Focus |
|------|-------|
| `test_data_preparation.py` | Dataset size, schema fields, embedding generation sanity check |
| `test_query_processing.py` | Hybrid vs keyword vs semantic behavior; result ordering |
| `test_threat_analysis.py` | Feature extraction & scorer output ranges; threat level mapping |
| `test_keyword_logic.py` | Tokenization, stop‑word filtering, keyword match caps |
| `test_integration_search_keywords.py` | Combined search + keyword overlay correctness |
| `test_natural_language_queries.py` | Phrases from task spec produce non‑empty results |
| `test_cache_and_latency.py` | Query caching enabled & latency improvement on repeat |
| `test_query_results_cache.py` | LRU/TTL behavior & cache hit detection |
| `test_example_queries.py` | Example queries produce expected minimum result counts |
| `test_threat_analysis.py` | Threat feature scores lead to correct level thresholds |

### CLI Tests (`tests/cli/`)
| File | Focus |
|------|-------|
| `test_cli_basic.py` | Single query invocation, JSON output shape, threshold filtering logic |

### End‑to‑End API Tests (`tests/e2e/`)
| File | Focus |
|------|-------|
| `test_api_search.py` | /api/v1/search returns structured results & metadata |
| `test_api_refine.py` | Refinement endpoint filters prior results correctly |
| `test_api_chat.py` | Chat endpoint manages session state & suggestions |
| `test_api_health_root.py` | Health + root endpoints respond with expected shape |

## Running Tests
Use the Makefile target (fastest):
```bash
make test
```

With coverage report:
```bash
make coverage
```

Direct pytest (inside virtualenv):
```bash
pytest -q          # all tests
pytest tests/unit  # only unit tests
pytest tests/e2e/test_api_search.py::test_api_search_basic  # single test
```

## Selective Execution Examples
Run only CLI tests:
```bash
pytest tests/cli -q
```

Run tests matching a keyword (e.g. 'cache'):
```bash
pytest -k cache -q
```

Stop after first failure:
```bash
pytest -x
```

Verbose output for debugging:
```bash
pytest -vv
```

Generate an HTML coverage report:
```bash
pytest --cov=src --cov-report=html
open htmlcov/index.html  # or xdg-open on Linux
```

## Test Data & Isolation
- Synthetic dataset is generated during bootstrap (150 emails). Tests assume it exists; rebuild with `make bootstrap` or `python app.py --setup` if missing.
- No external network calls are required; API tests run against an in‑process FastAPI app via test client.
- Caches are exercised but bounded (LRU size & TTL) to avoid side effects.

## Performance Notes
- Embedding model loads once; first search-related tests may take slightly longer.
- Repeated query tests assert latency decrease when cache hits occur.
- No test should rely on real wall‑clock delays; TTL expiry is simulated or uses short windows where needed.

## Refactoring Safety Nets
These tests collectively catch:
- Collection name or path changes that lead to empty search results.
- Threat scoring threshold regressions (e.g., all results filtered out).
- Explanation structure changes (fields missing or renamed).
- Cache misconfiguration leading to exceptions instead of graceful fallback.

## Adding New Tests
1. Pick appropriate directory (unit for isolated logic, e2e for API routes, cli for interface calls).
2. Use existing fixtures from `conftest.py` where possible.
3. Keep test names descriptive: `test_<component>_<behavior>()`.
4. Avoid brittle assertions on full strings—prefer key field presence or numeric ranges.
5. If adding a new feature flag or environment variable, include a test for its default behavior.

## Common Issues & Fixes
| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| Empty search results | Index not built | Run `make bootstrap` or `python app.py --setup` |
| Failing threshold test | Scores below chosen threshold | Lower threshold (e.g. 0.3) or adjust weights |
| Cache test failing | TTL too short / env override | Check environment vars (`ENABLE_QUERY_CACHE`) |
| Import errors | Missing PYTHONPATH | Ensure `PYTHONPATH=src` when custom running |

## When to Re‑Run Full Suite
- After changing scoring or feature extraction logic.
- After modifying index builder or collection name.
- Before submitting / deploying.

## Future Enhancements (Not Yet Implemented)
- Snapshot tests for explanations (structured JSON diff).
- Benchmark test measuring average search latency.
- Mutation tests for scoring robustness.

---
**Summary:** This test suite ensures the phishing threat hunting pipeline remains reliable, performant, and explainable as the code evolves. Keep it lean, fast, and focused on user‑visible behavior and critical internal invariants.
