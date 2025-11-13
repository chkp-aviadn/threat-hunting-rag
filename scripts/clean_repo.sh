#!/usr/bin/env bash
set -euo pipefail

# safe cleanup script for threat-hunting-rag
# Removes ephemeral caches, logs, transient example artifacts.
# Does NOT delete: data/chroma (vector DB), data/emails.csv, .venv (unless --venv flag), persistent docs.
# Usage: bash scripts/clean_repo.sh [--with-index] [--with-venv]
#   --with-index : also remove data/chroma (will need make rebuild-index)
#   --with-venv  : also remove local .venv directory

WITH_INDEX=0
WITH_VENV=0

for arg in "$@"; do
  case "$arg" in
    --with-index) WITH_INDEX=1 ;;
    --with-venv) WITH_VENV=1 ;;
    *) echo "[clean_repo] Unknown argument: $arg"; exit 1 ;;
  esac
done

echo "[clean_repo] Starting cleanup..."

# Python bytecode caches
find . -type d -name "__pycache__" -exec rm -rf {} + || true

# Tool caches / coverage
rm -rf .mypy_cache .pytest_cache .coverage htmlcov || true

# Logs & tmp
rm -f logs/*.log 2>/dev/null || true
rm -f tmp/* 2>/dev/null || true

# Transient example session artifacts (keep canonical real sample outputs)
rm -f examples/interactive_queries_latest.* || true
rm -f examples/interactive_queries_summary_* || true
rm -f examples/interactive_session_* || true
rm -f examples/sample_outputs_latest.json || true

# Embedding caches inside src/shared/cache (safe to delete - regenerated on demand)
rm -rf src/shared/cache/embeddings_cache || true
rm -rf src/shared/cache/models_cache || true
rm -rf src/shared/cache/query_cache || true

# Optional index removal
if [ "$WITH_INDEX" -eq 1 ]; then
  echo "[clean_repo] Removing Chroma index data/chroma/"
  rm -rf data/chroma || true
fi

# Optional venv removal
if [ "$WITH_VENV" -eq 1 ]; then
  echo "[clean_repo] Removing local virtual environment .venv/"
  rm -rf .venv || true
fi

echo "[clean_repo] Cleanup complete."