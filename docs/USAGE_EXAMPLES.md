# Threat Hunting RAG - Usage Examples

Below are 10 practical commands (API via curl and CLI) to exercise core functionality. Adjust `API_KEY` and port as needed.

## 1. Health Check
```bash
curl -s -H 'X-API-Key: demo-key-12345' http://127.0.0.1:8000/api/v1/health | python -m json.tool
```

## 2. Basic Hybrid Search
```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/search \
  -H 'Content-Type: application/json' -H 'X-API-Key: demo-key-12345' \
  -d '{"query":"urgent payment request from new sender","max_results":10,"search_method":"hybrid","include_explanations":true}' | python -m json.tool | head -n 40
```

## 3. Threshold Filtered Search
```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/search \
  -H 'Content-Type: application/json' -H 'X-API-Key: demo-key-12345' \
  -d '{"query":"invoice urgent domain suspicious","max_results":8,"search_method":"hybrid","threat_threshold":0.4,"include_explanations":true}' | python -m json.tool | head -n 40
```

## 4. Refinement (After Previous Request)
Replace PREV_ID with a real request_id from step 2.
```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/search/refine \
  -H 'Content-Type: application/json' -H 'X-API-Key: demo-key-12345' \
  -d '{"previous_request_id":"PREV_ID","adjust_threshold":0.8,"limit":5}' | python -m json.tool
```

## 5. Start Chat Session
```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/chat \
  -H 'Content-Type: application/json' -H 'X-API-Key: demo-key-12345' \
  -d '{"message":"wire transfer authorization","limit":5}' | python -m json.tool | head -n 40
```

## 6. Chat Refine Turn
Replace SESSION_ID from step 5.
```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/chat \
  -H 'Content-Type: application/json' -H 'X-API-Key: demo-key-12345' \
  -d '{"message":"refine suspicious attachments","session_id":"SESSION_ID","refine":true,"limit":5,"min_threat_score":0.3}' | python -m json.tool | head -n 40
```

## 7. Oversized Query (Expect 422)
```bash
python - <<'PY' | curl -s -X POST http://127.0.0.1:8000/api/v1/search -H 'Content-Type: application/json' -H 'X-API-Key: demo-key-12345' -d @- | python -m json.tool
import json
print(json.dumps({"query":"x"*600,"max_results":5,"search_method":"hybrid"}))
PY
```

## 8. CLI Hybrid Search
```bash
./.venv/bin/python -m src.interfaces.cli.app --query 'urgent payment request from new sender' --search-method hybrid --max-results 5 --output-format human
```

## 9. CLI Threshold / Refinement Simulation
```bash
./.venv/bin/python -m src.interfaces.cli.app --query 'invoice overdue urgent threshold0.6' --search-method hybrid --max-results 3 --output-format human
```

## 10. Rate Limit Stress (Optional Slow Test)
```bash
for i in $(seq 1 60); do curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8000/api/v1/search -H 'Content-Type: application/json' -H 'X-API-Key: demo-key-12345' -d '{"query":"rate limit test","max_results":1,"search_method":"hybrid"}' ; sleep 0.5; done | sort | uniq -c
```

---
### Tips
- Use `python app.py --validate` after dependency changes.
- If Chroma index warnings appear in CLI, run an API search first to warm components.
- Logs live under `logs/`; raw JSON artifacts from QA runs in `tmp/`.

### Cleanup Old Artifacts
```bash
find tmp -name '*_resp.json' -mtime +3 -delete
```
