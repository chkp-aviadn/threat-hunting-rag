# Threat Hunting RAG System

A Retrieval-Augmented Generation (RAG) system for phishing threat hunting that analyzes email datasets through natural language queries and returns ranked, explainable threat detections.

## 🎯 Overview
Ask: *"Show me emails with urgent payment requests from new senders"* → System performs hybrid (semantic + keyword) retrieval, extracts threat features (urgency, impersonation, attachments, financial / credential signals), scores each email, and produces human + optional JSON explanations. Refinement lets you quickly narrow results without re-running vector search.

## 🚀 Quick Start (Makefile)
Use provided targets for one-command setup and launch.


---
## 1. What’s Inside

| Component | Purpose |
|-----------|---------|
| `data/` | Synthetic email dataset (generated, 150 samples) + Chroma vector index |
| `src/query_processing/` | Hybrid semantic + keyword search service |
| `src/threat_analysis/` | Feature extraction (urgency, attachments, impersonation) + scoring |
| `src/orchestration/` | Pipeline that blends retrieval + analysis + explanations |
| `src/interfaces/cli/` | CLI: single queries & interactive refinement |
| `src/interfaces/api/` | Minimal REST API (search, refine, chat, health) |
| `examples/` | Query examples documentation & automated CLI test script |
| `diagrams/architecture.mmd` | Mermaid architecture diagram |
| `docs/planning/` | Task description and planning notes (advanced docs coming later) |

Full reference docs:
| Topic | File |
|-------|------|
| Architecture | [`docs/architecture.md`](docs/architecture.md) |
| Scoring Logic | [`docs/scoring.md`](docs/scoring.md) |
| Performance Guide | [`docs/performance.md`](docs/performance.md) |
| Caching Details | [`docs/cache.md`](docs/cache.md) |
| Interfaces (CLI/API) | [`docs/interfaces.md`](docs/interfaces.md) |
| Security (Baseline) | [`docs/security.md`](docs/security.md) |
| Test Suite Overview | [`tests/README.md`](tests/README.md) |


---
## 2. Quick Start

```bash
git clone <repo-url>
cd threat-hunting-rag
python -m venv .venv && source .venv/bin/activate
make bootstrap      # installs deps + generates dataset + builds vector index
make cli            # run a quick interactive query session
# OR
make api            # start REST API (http://127.0.0.1:8000)
```

If not using `make`:
```bash
python app.py --setup      # dataset + index check
python app.py --cli        # CLI interface
python app.py --api        # API server
```

Create env file (optional overrides):
```bash
cp .env.example .env
```

---
## 3. Docker Deployment

Run the system in Docker for isolated, portable execution.

### Quick Start with Docker

```bash
# Build the Docker image
make docker-build

# Run interactive CLI
make docker-cli

# Run API server (detached, port 8000)
make docker-api
```

### Docker Commands via Makefile

| Target | What it does |
|--------|--------------|
| `make docker-build` | Build Docker image |
| `make docker-cli` | Run interactive CLI in Docker |
| `make docker-api` | Start API server in Docker (detached, port 8000) |

### Docker Modes

The container supports different modes via `MODE` environment variable:
- `cli-interactive` - Full interactive CLI with refinement (used by `docker-cli`)
- `api` - REST API server (used by `docker-api`)

Direct usage:
```bash
# Interactive CLI
docker run -it --rm \
  -e MODE=cli-interactive \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/cache:/app/cache \
  -v $(pwd)/logs:/app/logs \
  --env-file .env \
  threat-hunting-rag

# API server
docker run -d --name threat-hunting-rag-api \
  -e MODE=api \
  -p 8000:8000 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/cache:/app/cache \
  -v $(pwd)/logs:/app/logs \
  --env-file .env \
  threat-hunting-rag
```

### Managing API Container

```bash
# Check logs
docker logs -f threat-hunting-rag-api

# Stop container
docker stop threat-hunting-rag-api

# Test API
curl http://localhost:8000/health
```

### Data Persistence

Docker setup uses volume mounts for persistence:
- `./data` - Email dataset and ChromaDB vector index
- `./cache` - Embeddings and model cache
- `./logs` - Application logs

These directories are **NOT** copied into the Docker image; they're mounted at runtime for data persistence and smaller image size.

For full Docker documentation, see [`DOCKER.md`](DOCKER.md).

---
## 4. Makefile Essentials

| Target | What it does |
|--------|--------------|
| `make bootstrap` | Create venv, install requirements, regenerate dataset & index |
| `make cli` | Launch CLI single‑query mode (non‑interactive) |
| `make query` | Prompt for one ad‑hoc query (terminal read) |
| `make api` | Start FastAPI server (port 8000) |
| `make rebuild-index` | Rebuild embeddings & Chroma index (keeps data) |
| `make full-reset` | Clean caches & index, regenerate everything |
| `make clean` | Remove logs, caches, temp artifacts (safe) |
| `make test` | Run test suite quickly |
| `make coverage` | Run tests w/ coverage report |
| `make quick-api` | One-step: ensure venv + deps + dataset then start API |
| `make quick-cli` | One-step: ensure venv + deps + dataset then start interactive CLI |
| `make demo-interactive` | Run automated interactive CLI session with 10 example queries, generates report |

Tips:
- Use `full-reset` only when you want a fresh dataset & vectors.
- `rebuild-index` is faster (reuse dataset, rebuild vectors).
- All commands assume you activated the venv (`source .venv/bin/activate`).
- `demo-interactive` runs 10 predefined queries and generates JSON/Markdown reports in `examples/`

### 3.1 Setup Command Differences

Three frequently confused targets / commands handle different layers of initialization:

| Command | Creates venv | Installs deps | Generates / validates dataset & index | Purpose |
|---------|--------------|---------------|---------------------------------------|---------|
| `make install` | No | Yes (system python or active venv) | No | Just ensure Python dependencies are present |
| `make setup` | No | No | Yes (via `python app.py --setup`) | Build or validate data & vector index assuming deps already installed |
| `make bootstrap` | Yes (if missing) | Yes (inside new venv) | Yes (via `scripts/regenerate_all.py`) | Full first-time environment provisioning |
| `make quick-api` | Yes (if missing) | Yes | Conditional (runs setup if dataset missing) | Fast start to API service |
| `make quick-cli` | Yes (if missing) | Yes | Conditional (runs setup if dataset missing) | Fast start to interactive CLI |

When to choose:
- Fresh clone: `make bootstrap` then `make api` or `make quick-api` directly.
- Dependencies changed (no data changes): `make install`.
- Data/index corrupted or removed: `make setup` (or `make rebuild-index` / `make full-reset` depending on depth).
- Want immediate API or CLI without manual steps: `make quick-api` / `make quick-cli`.

Rule of thumb: bootstrap = comprehensive first-time setup; install = packages only; setup = data/index only; quick-* = convenience wrappers.

---
## 5. Using the CLI

Run a single query (human output):
```bash
python app.py --query "urgent payment request from new sender"
```

JSON output for automation:
```bash
python app.py --query "executive impersonation" --output json --limit 5
```

Apply a threat score threshold (filters low scored results):
```bash
python app.py --query "suspicious attachment invoice" --threshold 0.4 --limit 8 --output json
```

Interactive mode (continuous queries + refinement):
```bash
python -m src.interfaces.cli.app --interactive
```
### 5.1 Interactive CLI Capabilities

When you start `--interactive` you enter a small REPL that supports natural language queries and iterative refinement without rebuilding embeddings each time.

You can type commands (they are parsed by prefix):
```
query <text>          Run a new threat hunting query (natural language)
refine [opts]         Refine last results: threshold=, limit=, focus=
history               Show prior queries issued in this session
stats                 Basic session statistics (count, timing)
clear                 Clear the screen
exit | quit           Leave interactive mode
help                  Show help summary
```

Examples:
```
query urgent payment from unfamiliar sender
refine threshold=0.4 limit=5 focus=urgent
refine limit=3 focus=attachment
query executive impersonation wire transfer
refine threshold=0.6
```

Natural language support means you don't need structured syntax—phrases like:
```
"emails with suspicious attachment names"
"find urgent payment requests from new senders"
"credential harvesting attempts password reset"
"impersonation of executives requesting wire transfer"
```
are tokenized; semantic + keyword hybrid search finds relevant emails; threat features (urgency, financial request, credential harvest signals, impersonation, suspicious attachments, unknown sender domain patterns) are extracted for each result and blended into the `threat_score`.

### 5.2 Iterative Refinement Explained

Refinement lets you drill down on the PREVIOUS result set without repeating vector search:
1. Run a broad query: `query urgent payment`
2. Inspect results (maybe 8 MEDIUM scores, some LOW)
3. Narrow by raising threshold: `refine threshold=0.5` (keeps higher risk items only)
4. Focus on a feature: `refine focus=attachment` (filters to items whose detected indicators mention attachments)
5. Reduce clutter: `refine limit=3` (top 3 after previous filters)

Behind the scenes refinement does:
```
filtered = [r for r in previous_results if r.threat_score >= threshold]
if focus: keep results where feature name or detected indicator contains focus token
limit: slice first N (rank preserved / re-ranked sequentially)
```
No additional embedding generation or database query occurs; it's fast and ideal for triage.

Use cases:
| Scenario | Query | Refinement |
|----------|-------|-----------|
| Narrow urgency + payment fraud | `query urgent payment request` | `refine threshold=0.5 focus=urgent` |
| Attachment triage | `query suspicious attachment invoice` | `refine focus=attachment limit=5` |
| Executive compromise drill-down | `query executive impersonation wire transfer` | `refine threshold=0.6` |
| Credential harvest escalation | `query password reset verify account` | `refine threshold=0.4 focus=credential` |

What "iterative" means here: each `refine` stacks on the latest displayed set. If you run a new `query` it resets the refinement chain.

### 5.3 Threat Score Interpretation In CLI

| Score Range | Level | Action |
|-------------|-------|--------|
| <0.20 | NEGLIGIBLE | Usually ignore |
| 0.20–0.39 | LOW | Monitor, maybe refine by feature |
| 0.40–0.59 | MEDIUM | Investigate context, verify sender |
| 0.60–0.79 | HIGH | Validate out-of-band, treat as suspicious |
| ≥0.80 | CRITICAL | Escalate immediately |

Raising `threshold` filters quickly toward HIGH/CRITICAL signals; lowering it broadens context.

### 5.4 Command Reference (Quick Table)
| Command | Parameters | Effect |
|---------|------------|--------|
| `query <text>` | free-form text | Executes new search (semantic + keyword) |
| `refine threshold=<f>` | float 0–1 | Keep results with `threat_score >= f` |
| `refine limit=<n>` | int | Trim to first n ranked results |
| `refine focus=<term>` | feature/indicator token | Keep results whose indicators mention the term |
| `history` | — | Show past query strings this session |
| `stats` | — | Show number of queries & timing summary |
| `clear` | — | Clears screen output |
| `help` | — | Prints usage summary |
| `exit` / `quit` | — | Terminates interactive session |

### 5.5 Tips
- Start broad (`query payment request`) then refine by raising threshold.
- Combine focus with threshold: `refine focus=urgent threshold=0.5` (order doesn't matter in command parsing; both tokens read).
- If refinement yields zero items, lower threshold or remove focus to recover broader context.
- Use JSON output for automation outside interactive mode with `--output json` on single queries.

Meaning of key options:
| Option | Meaning |
|--------|---------|
| `limit` | Max results to return |
| `threshold` | Minimum threat score (0–1) retained |
| `focus` (refine) | Highlight / keep results with matching indicator (e.g. urgent, attachment) |

Typical queries:
```bash
python app.py --query "show emails with suspicious attachment names"
python app.py --query "find executive impersonation attempts" --limit 5
python app.py --query "credential harvesting reset password" --threshold 0.3
```

Exit interactive mode with `exit` or `quit`.

---
## 6. REST API

Start server:
```bash
make api
# or
python app.py --api
```

Default key for local testing (from code): `demo-key-12345` sent in `X-API-Key` header.

### Endpoints
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/` | Root metadata |
| GET | `/api/v1/health` | Health & uptime summary |
| POST | `/api/v1/search` | Run a threat hunting query |
| POST | `/api/v1/search/refine` | Refine a previous search by request id |
| POST | `/api/v1/chat` | Chat style querying + optional automatic refinement |

### Examples (copy & run)

Health:
```bash
curl -s -H "X-API-Key: demo-key-12345" http://127.0.0.1:8000/api/v1/health | jq
```

Search:
```bash
curl -s -H "X-API-Key: demo-key-12345" -H "Content-Type: application/json" \
	-d '{
		"query": "urgent payment requests from new senders",
		"max_results": 5,
		"threat_threshold": 0.3,
		"search_method": "hybrid",
		"include_explanations": true
	}' \
	http://127.0.0.1:8000/api/v1/search | jq
```

Refine (replace PREV_ID with request_id returned by /search):
```bash
curl -s -H "X-API-Key: demo-key-12345" -H "Content-Type: application/json" \
	-d '{
		"previous_request_id": "PREV_ID",
		"adjust_threshold": 0.4,
		"limit": 3,
		"add_filters": {"sender_domain": "example.com"},
		"explanation_focus": "urgent"
	}' \
	http://127.0.0.1:8000/api/v1/search/refine | jq
```

Chat:
```bash
curl -s -H "X-API-Key: demo-key-12345" -H "Content-Type: application/json" \
	-d '{
		"message": "show executive impersonation attempts",
		"limit": 5,
		"min_threat_score": 0.3
	}' \
	http://127.0.0.1:8000/api/v1/chat | jq
```

Chat refinement (reuse session_id + set refine=true):
```bash
curl -s -H "X-API-Key: demo-key-12345" -H "Content-Type: application/json" \
	-d '{
		"message": "narrow to high urgency",
		"session_id": "SESSION_ID",
		"refine": true,
		"focus_feature": "urgent",
		"min_threat_score": 0.4
	}' \
	http://127.0.0.1:8000/api/v1/chat | jq
```

### Response Fields (search)
| Field | Meaning |
|-------|---------|
| `threat_score` | Composite 0–1 score (higher = more suspicious) |
| `threat_level` | NEGLIGIBLE / LOW / MEDIUM / HIGH / CRITICAL |
| `explanation` | Human summary (features + similarity) |
| `explanation_structured` | Structured JSON (if mode=json requested) |
| `keyword_matches` | Query tokens found in the email |

---
## 7. Refinement Concept
Refinement does NOT re-run a vector search; it filters & re-ranks previous results (apply threshold, focus feature, limit). This is faster and allows quick "drill down" after a broad initial query.

---
## 8. Threat Scoring (Simple View)
Scores blend:
- Semantic similarity
- Detected feature confidence (urgent language, suspicious attachment, impersonation, new sender)
- Minor keyword boosts

Levels:
| Level | Score ≥ |
|-------|---------|
| LOW | 0.2 |
| MEDIUM | 0.4 |
| HIGH | 0.6 |
| CRITICAL | 0.8 |

---
## 9. Advanced Documentation
| Topic | File |
|-------|------|
| Detailed architecture & data flow | [`docs/architecture.md`](docs/architecture.md) |
| Scoring math & feature weighting | [`docs/scoring.md`](docs/scoring.md) |
| Caching strategy & performance | [`docs/performance.md`](docs/performance.md) |
| Cache implementation details | [`docs/cache.md`](docs/cache.md) |
| Interfaces (CLI/API) guide | [`docs/interfaces.md`](docs/interfaces.md) |
| Security & hardening checklist | [`docs/security.md`](docs/security.md) |
| Test suite overview | [`tests/README.md`](tests/README.md) |

Planning references: `docs/planning/task.txt`, `docs/planning/plan.md`, `diagrams/architecture.mmd`.

---
## 10. Troubleshooting Quick List
| Symptom | Fix |
|---------|-----|
| `ModuleNotFoundError: interfaces` | Use `make api` (PYTHONPATH set) or run `python app.py --api` |
| Empty results with high threshold | Lower threshold (e.g. 0.3) or remove it to inspect raw set |
| Slow first query | Warm-up embedding model – subsequent queries are faster |
| Curl 401 Unauthorized | Missing `X-API-Key` header (use `demo-key-12345`) |

---
## 11. License & Disclaimer
Synthetic dataset & system are for demonstration / evaluation only. Do not rely solely on these heuristics for production phishing defense without additional validation and monitoring.

---
Happy Hunting! 🔍
