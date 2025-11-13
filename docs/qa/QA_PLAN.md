# Threat Hunting RAG System – End-User QA Plan

This document tracks manual, user-centric QA of the minimal REST API and CLI interfaces. Each step should record: timestamp, command/request, response summary, observed latency, and any anomalies.

## Legend
- Status: ☐ Pending | ✅ Done | ⚠ Issue Found
- Latency Target: < 150ms per search (typical observed 20–60ms warm)

## Environment Assumptions
- OS: Linux
- Python: 3.11
- Branch: `main`
- Working directory: repository root

## Core Functional Objectives to Validate
1. Dataset present & embeddings accessible
2. API health & root metadata reachable
3. Search returns ranked results with explanations & threat levels
4. Cache improves repeated query latency & logs cache hits
5. Threshold filtering works (filters below min score)
6. Refinement endpoint alters result set deterministically
7. Chat endpoint maintains session context and supports refinement
8. CLI single query output with explanations & threat levels
9. CLI threshold & refine operations
10. Keyword-only queries produce appropriate boosts & explanation keywords
11. Performance cold vs warm queries
12. Robust error handling for malformed input / boundary conditions
13. Logs contain required events (SEARCH, RESULTS, cache hits/misses)
14. Threat level mapping conforms to defined thresholds
15. Optional Redis disabled path works (no crashes)

## Test Data / Sample Queries
| ID | Query | Purpose |
|----|-------|---------|
| Q1 | urgent payment request from new sender | Hybrid high-threat | 
| Q2 | invoice urgent domain suspicious | Threshold filtering |
| Q3 | wire transfer authorization | High-value finance |
| Q4 | refine suspicious attachments | Chat refinement |
| Q5 | verify account credentials | Phishing impersonation |
| Q6 | attachment malware scan pending | Keyword detection |
| Q7 | executive impersonation urgent | Escalated context |
| Q8 | password reset notification | Legitimate vs phishing mix |
| Q9 | suspicious domain typos | Keyword & domain analysis |
| Q10 | urgent billing overdue invoice | Cache + hybrid |

## Step Checklist
| Step | Status | Description | Artifact(s) |
|------|--------|-------------|-------------|
| 1 | ✅ | Environment bootstrap & setup | Setup log (150 emails, fresh index) |
| 2 | ☐ | API health & root | /health & / responses |
| 3 | ☐ | Initial search (Q1) | JSON response, latency |
| 4 | ☐ | Cache verification (repeat Q1) | Latency improvement, log cache hit |
| 5 | ☐ | Threshold filtering (Q2) | Fewer results, min score >= threshold |
| 6 | ☐ | Refinement endpoint | Before/after diff |
| 7 | ☐ | Chat session + refine | session_id continuity |
| 8 | ☐ | CLI basic query (Q3) | CLI output |
| 9 | ☐ | CLI threshold + refine (Q2 → refine) | Filter + change |
| 10 | ☐ | Keyword-only (Q6) | Explanation keywords list |
| 11 | ☐ | Performance cold vs warm (Q10) | Timings table |
| 12 | ☐ | Error handling (too long query) | Error JSON |
| 13 | ☐ | Logging review | app.log excerpts |
| 14 | ☐ | Threat level mapping validation | Score→Level table |
| 15 | ☐ | Redis disabled confirmation | Startup log (no Redis) |
| 16 | ☐ | Summary & sign-off | Final notes |

## Documentation for Each Recorded Step
For each step record:
```
### Step <n>: <Title>
Timestamp:
Command / Request:
Response (key fields):
Latency (ms):
Threat Levels distribution (if applicable):
Cache Hit (if applicable):
Notes / Issues:
```

## Commands Reference (for convenience)

### Environment & Setup
```bash
python -m venv .venv
source .venv/bin/activate
cp .env.example .env
pip install -r requirements.txt
python app.py --setup
```

### Run API
```bash
python app.py --api
```
Access docs: http://localhost:8000/docs

### Sample API Requests (use curl or HTTP client)
```bash
# Health
curl -s http://localhost:8000/api/v1/health | jq

# Root
curl -s http://localhost:8000/ | jq

# Search (Q1)
curl -s -X POST http://localhost:8000/api/v1/search \
  -H 'Content-Type: application/json' \
  -d '{"query":"urgent payment request from new sender","limit":5,"method":"hybrid"}' | jq

# Repeat Search (Q1) for cache
curl -s -X POST http://localhost:8000/api/v1/search \
  -H 'Content-Type: application/json' \
  -d '{"query":"urgent payment request from new sender","limit":5,"method":"hybrid"}' | jq

# Threshold Filtering (Q2)
curl -s -X POST http://localhost:8000/api/v1/search \
  -H 'Content-Type: application/json' \
  -d '{"query":"invoice urgent domain suspicious","limit":8,"method":"hybrid","min_threat_score":0.4}' | jq

# Refinement (after Q1)
curl -s -X POST http://localhost:8000/api/v1/search/refine \
  -H 'Content-Type: application/json' \
  -d '{"query":"urgent payment request from new sender","previous_results":[],"limit":5,"focus_feature":"urgent","min_threat_score":0.5}' | jq

# Chat (start session)
curl -s -X POST http://localhost:8000/api/v1/chat \
  -H 'Content-Type: application/json' \
  -d '{"message":"wire transfer authorization","limit":5}' | jq

# Chat refine (use returned session_id)
# Replace <SESSION_ID> with actual value
curl -s -X POST http://localhost:8000/api/v1/chat \
  -H 'Content-Type: application/json' \
  -d '{"message":"refine suspicious attachments","limit":10,"session_id":"<SESSION_ID>","refine":true,"min_threat_score":0.3}' | jq
```

### CLI Examples
```bash
python interfaces/cli/app.py --query "wire transfer authorization" --limit 5 --method hybrid
python interfaces/cli/app.py --query "invoice urgent domain suspicious" --limit 8 --method hybrid --threshold 0.4
python interfaces/cli/app.py --chat --limit 5 --threshold 0.3
```

### Performance Sampling (Manual)
Repeat a query before and after warm-up:
```bash
# Cold
python interfaces/cli/app.py --query "urgent billing overdue invoice" --limit 5 --method hybrid
# Warm
python interfaces/cli/app.py --query "urgent billing overdue invoice" --limit 5 --method hybrid
```

### Error Handling (Too Long Query)
```bash
python interfaces/cli/app.py --query "$(python -c 'print("x"*600)')" --limit 5 --method hybrid
```
Expect rejection or sanitized handling if length > MAX_QUERY_LENGTH.

## Threat Level Thresholds (For Validation)
| Level | Range |
|-------|-------|
| NEGLIGIBLE | < 0.20 |
| LOW | [0.20, 0.40) |
| MEDIUM | [0.40, 0.60) |
| HIGH | [0.60, 0.80) |
| CRITICAL | ≥ 0.80 |

## Anomalies & Notes
### Dataset Phishing Count Discrepancy
- During reset rebuild, intermediate log line reported: `Phishing: 27, Legitimate: 123`.
- Final summary reported: `150 emails (45 phishing)`.
- Direct CSV inspection confirmed: 150 total (105 False, 45 True).
Interpretation: Early count likely taken before final label assignment/enrichment (or outdated stat source). Actual dataset is consistent; no action required beyond noting mismatch.


## Log Lines to Confirm
- `SEARCH | query=... method=...`
- `RESULTS | total=... levels=[...] avg_threat=... cache_hit=...`
- Cache hit lines from `shared.cache.query_cache`

## Completion Criteria
All steps marked ✅ with no blocking issues; performance within targets; explanations & threat levels consistent; cache functioning; error paths safe.

## Final Summary Section (to fill after execution)
```
### Summary
Total Steps Completed: X / 16
Performance (avg warm latency): Y ms
Issues Found: (list or 'None')
Recommended Follow-ups: (list)
```
