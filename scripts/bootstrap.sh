#!/usr/bin/env bash
# Threat Hunting RAG System – Bootstrap Script
# -------------------------------------------------------------
# Automates environment creation, dependency installation,
# system setup, validation, and prints usage examples.
#
# Usage:
#   bash scripts/bootstrap.sh                # full bootstrap
#   bash scripts/bootstrap.sh --skip-install # assume deps installed
#   bash scripts/bootstrap.sh --force-reset  # wipe & rebuild dataset/index
#   bash scripts/bootstrap.sh --start-api    # start API server after setup
#   bash scripts/bootstrap.sh --help         # help
#
# Idempotent: re-runs setup only if needed unless --force-reset.
# -------------------------------------------------------------
set -euo pipefail
IFS=$'\n\t'

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${PROJECT_ROOT}/.venv"
PYTHON_BIN="python3"
FORCE_RESET=false
SKIP_INSTALL=false
START_API=false
LOG_FILE="${PROJECT_ROOT}/logs/bootstrap_run.log"

function log() { echo -e "$(date +'%Y-%m-%d %H:%M:%S') | $*" | tee -a "$LOG_FILE"; }

function help_text() {
  cat <<'EOF'
Threat Hunting RAG Bootstrap
Options:
  --skip-install    Skip dependency installation
  --force-reset     Remove dataset, vector index, caches then rebuild
  --start-api       Launch API server after setup (foreground)
  --help            Show this help
EOF
}

for arg in "$@"; do
  case "$arg" in
    --force-reset) FORCE_RESET=true ;;
    --skip-install) SKIP_INSTALL=true ;;
    --start-api) START_API=true ;;
    --help) help_text; exit 0 ;;
    *) echo "Unknown argument: $arg"; help_text; exit 1 ;;
  esac
done

mkdir -p "${PROJECT_ROOT}/logs" || true
log "Bootstrap started (force_reset=${FORCE_RESET}, skip_install=${SKIP_INSTALL}, start_api=${START_API})"

# 1. Ensure Python available
if ! command -v ${PYTHON_BIN} >/dev/null 2>&1; then
  log "ERROR: python3 not found in PATH"; exit 1
fi

# 2. Create venv if missing
if [[ ! -d "$VENV_DIR" ]]; then
  log "Creating virtual environment at $VENV_DIR"
  ${PYTHON_BIN} -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
log "Using Python: $(python -V)"

# 3. Install dependencies
if [[ "$SKIP_INSTALL" = false ]]; then
  if [[ -f "$PROJECT_ROOT/requirements.txt" ]]; then
    log "Installing requirements.txt dependencies"
    pip install -r "$PROJECT_ROOT/requirements.txt" >> "$LOG_FILE" 2>&1
  else
    log "requirements.txt missing; falling back to pyproject (editable install)"
    pip install -e "$PROJECT_ROOT" >> "$LOG_FILE" 2>&1
  fi
fi

# 4. Ensure .env exists
if [[ ! -f "$PROJECT_ROOT/.env" ]]; then
  if [[ -f "$PROJECT_ROOT/.env.example" ]]; then
    cp "$PROJECT_ROOT/.env.example" "$PROJECT_ROOT/.env"
    log "Copied .env.example to .env"
  else
    cat > "$PROJECT_ROOT/.env" <<'MINENV'
EMAIL_DATASET_PATH=data/emails.csv
VECTOR_DB_PATH=data/chroma
EMBEDDING_MODEL=sentence-transformers/all-MiniLM-L6-v2
MAX_RESULTS=10
API_KEY=demo-key-12345
DEBUG=false
MINENV
    log "Created minimal .env"
  fi
fi

cd "$PROJECT_ROOT"

# 5. Reset if requested
if [[ "$FORCE_RESET" = true ]]; then
  log "Force reset requested"
  python app.py --reset || { log "Reset failed"; exit 1; }
else
  log "Running setup (idempotent)"
  python app.py --setup || { log "Setup failed"; exit 1; }
fi

# 6. Validate
log "Validating system state"
if python app.py --validate >> "$LOG_FILE" 2>&1; then
  log "Validation passed"
else
  log "Validation FAILED"; exit 1
fi

# 7. Dataset quick stats
if [[ -f data/emails.csv ]]; then
  COUNT_LINE=$(python - <<'PY'
import pandas as pd
try:
  df=pd.read_csv('data/emails.csv')
  phishing=df['is_phishing'].sum()
  total=len(df)
  legit=total-phishing
  print(f"Dataset: total={total} phishing={phishing} legitimate={legit}")
except Exception as e:
  print(f"Dataset read error: {e}")
PY
)
  log "$COUNT_LINE"
else
  log "Dataset file missing after setup"
fi

# 8. Usage Examples (10)
cat <<'EXAMPLES'
-------------------------------------------------------------
USAGE EXAMPLES (run inside activated virtual environment)
-------------------------------------------------------------
# 1. Start API server
python app.py --api
# (Docs: http://127.0.0.1:8000/docs)

# 2. Basic search (hybrid)
curl -s -H 'Content-Type: application/json' -H 'X-API-Key: demo-key-12345' \
  -d '{"query":"urgent payment request from new sender","max_results":5,"search_method":"hybrid"}' \
  http://127.0.0.1:8000/api/v1/search | jq '.results[0]'

# 3. Repeat same search (observe faster latency / cache)
curl -s -H 'Content-Type: application/json' -H 'X-API-Key: demo-key-12345' \
  -d '{"query":"urgent payment request from new sender","max_results":5,"search_method":"hybrid"}' \
  http://127.0.0.1:8000/api/v1/search | jq '.processing_time_ms'

# 4. Threshold filtering
curl -s -H 'Content-Type: application/json' -H 'X-API-Key: demo-key-12345' \
  -d '{"query":"invoice urgent domain suspicious","max_results":8,"search_method":"hybrid","threat_threshold":0.4}' \
  http://127.0.0.1:8000/api/v1/search | jq '.total_results'

# 5. Chat start
curl -s -H 'Content-Type: application/json' -H 'X-API-Key: demo-key-12345' \
  -d '{"message":"wire transfer authorization","limit":5}' \
  http://127.0.0.1:8000/api/v1/chat | jq '.session_id'

# 6. Chat refine (replace <SID>)
curl -s -H 'Content-Type: application/json' -H 'X-API-Key: demo-key-12345' \
  -d '{"message":"refine suspicious attachments","limit":5,"session_id":"<SID>","refine":true,"min_threat_score":0.3}' \
  http://127.0.0.1:8000/api/v1/chat | jq '.refined'

# 7. Refinement endpoint (after initial search obtain request_id)
# Suppose ORIGINAL_ID=<UUID> from previous search history
curl -s -H 'Content-Type: application/json' -H 'X-API-Key: demo-key-12345' \
  -d '{"previous_request_id":"<ORIGINAL_ID>","adjust_threshold":0.6,"limit":5}' \
  http://127.0.0.1:8000/api/v1/search/refine | jq '.total_results'

# 8. CLI single query
python -m src.interfaces.cli.app --query "urgent billing overdue invoice" --limit 5

# 9. Oversized query error test
python -m src.interfaces.cli.app --query "$(python - <<'PY';print('x'*600);PY)" --limit 5 || echo "Expected failure due to length"

# 10. Health & root quick check
curl -s -H 'X-API-Key: demo-key-12345' http://127.0.0.1:8000/api/v1/health | jq '.status'
curl -s http://127.0.0.1:8000/ | jq '.endpoints'
-------------------------------------------------------------
EXAMPLES

log "Bootstrap complete. Activate venv with: source .venv/bin/activate"
if [[ "$START_API" = true ]]; then
  log "Starting API server (CTRL+C to stop)"
  exec python app.py --api
fi
