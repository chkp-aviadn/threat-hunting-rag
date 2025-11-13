# Interfaces Guide

## 1. Overview
Two primary interfaces:
- CLI (single query & interactive refinement)
- REST API (search, refine, chat, health)

Both leverage the same pipeline beneath (`rag_pipeline.py`).

## 2. CLI Modes
| Mode | Invocation | Description |
|------|------------|-------------|
| Single Query | `python app.py --query "text" [--threshold 0.4] [--limit 5]` | Executes one search, prints human or JSON output |
| Interactive | `python -m src.interfaces.cli.app --interactive` | REPL for iterative querying & refinement |
| Batch (file) | `python -m src.interfaces.cli.app --batch queries.txt --output results.json` | Processes multiple queries from file |
| Quick Start | `make quick-cli` | Ensures environment + dataset then launches interactive mode |

### 2.1 Interactive Commands
| Command | Effect |
|---------|-------|
| `query <text>` | New search (resets refinement chain) |
| `refine threshold=<f>` | Filter previous results by score ≥ f |
| `refine limit=<n>` | Trim result list to n |
| `refine focus=<term>` | Keep results whose indicators mention term |
| `history` | Show past queries |
| `stats` | Session summary (count, timing) |
| `clear` | Clear terminal output |
| `help` | Show usage summary |
| `exit / quit` | Leave interactive shell |

### 2.2 Output Formats
Use `--output-format human|json|table` (default human). JSON enables programmatic consumption and can include `explanation_structured` when pipeline runs in JSON explanation mode.

## 3. REST API Endpoints
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/health` | Health & version info |
| POST | `/api/v1/search` | Run a threat hunting query |
| POST | `/api/v1/search/refine` | Refine prior search results by request id |
| POST | `/api/v1/chat` | Session-based interactive querying & refinement |
| GET | `/` | Root metadata |

### 3.1 Search Payload (Example)
```json
{
  "query": "urgent payment requests from new senders",
  "max_results": 5,
  "threat_threshold": 0.3,
  "search_method": "hybrid",
  "include_explanations": true,
  "explanation_mode": "json",
  "detail_level": "detailed"
}
```

### 3.2 Search Response (Key Fields)
| Field | Description |
|-------|-------------|
| `request_id` | Identifier for reuse in refinement |
| `results[].threat_score` | Numerical risk score |
| `results[].threat_level` | NEGLIGIBLE..CRITICAL |
| `results[].explanation` | Human-readable multiline summary |
| `results[].explanation_structured` | JSON object (if `explanation_mode=json`) |
| `results[].keyword_matches` | List of matched tokens |

### 3.3 Refinement Request
```json
{
  "previous_request_id": "UUID-HERE",
  "adjust_threshold": 0.5,
  "limit": 3,
  "explanation_focus": "urgent"
}
```
Filters prior result set locally; no new vector DB call.

### 3.4 Chat Session
| Field | Meaning |
|-------|--------|
| `session_id` | Maintains conversational context |
| `message` | User natural language request |
| `refine` | If true, treat message as refinement instruction |
| `focus_feature` | Optional feature token (e.g., urgent) |
| `min_threat_score` | Score filter |

### 3.5 Chat Flow Internals
1. New session (no `session_id`) → create UUID.
2. Run pipeline query (or refinement if `refine=true`).
3. Append turn to `SessionStore` (Redis or memory).
4. Return results + session metadata.

## 4. Refinement Semantics (Shared)
Refinement never recomputes embeddings; it filters existing results by:
- Threat score threshold
- Focus term presence in indicators / explanation
- Limit
If filtering yields empty set, pipeline may fallback to original unfiltered set (prevents zero-result frustration).

## 5. Explanation Modes
| Mode | Result |
|------|--------|
| `text` | Multiline `explanation` string; `explanation_structured` null |
| `json` | Both human string and structured dict returned |

To force JSON structured explanation via API: set `"explanation_mode": "json"`. For CLI, ensure the query object propagates JSON mode when using `--output-format json` (feature may require minor wiring if absent).

## 6. Error Handling
| Scenario | Behavior |
|----------|---------|
| Invalid payload | 422 validation error (FastAPI) |
| Missing API key (auth enabled) | 401 Unauthorized |
| Unknown `previous_request_id` | Empty refinement result or 404 (implementation dependent) |
| Explainer failure | Fallback minimal explanation format |
| Cache / Redis exception | Logged; operation continues using non-cached path |

## 7. Quick Start Examples
CLI:
```bash
python app.py --query "executive impersonation wire transfer" --threshold 0.4 --limit 5 --output-format json
```
API (curl):
```bash
curl -s -H "X-API-Key: demo-key-12345" -H "Content-Type: application/json" \
  -d '{"query":"credential harvesting reset password","max_results":5,"explanation_mode":"json"}' \
  http://127.0.0.1:8000/api/v1/search | jq '.results[0] | {score: .threat_score, level: .threat_level}'
```
Refine via API:
```bash
curl -s -H "X-API-Key: demo-key-12345" -H "Content-Type: application/json" \
  -d '{"previous_request_id":"REQ-ID","adjust_threshold":0.5,"limit":3}' \
  http://127.0.0.1:8000/api/v1/search/refine | jq
```

## 8. Extensibility
| Addition | Where |
|----------|------|
| New endpoint | `api/app.py` (define Pydantic schema + route) |
| New CLI command | Extend interactive parser in `cli/app.py` |
| New output format | Modify CLI renderer; optionally add explanation mode handling |

## 9. Design Principles
- Fast iteration: refinement avoids repeated heavy retrieval.
- Separation of concerns: retrieval vs analysis vs presentation.
- Predictable output: stable explanation format for both human & machine consumption.

---
Use this guide to navigate and extend user-facing interfaces; pair with `architecture.md` for internal flow and `scoring.md` for risk logic.
