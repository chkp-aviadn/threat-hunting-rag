## Minimal Makefile: essential development and runtime commands

PYTHON ?= python
VENV ?= .venv
VENV_PY := $(VENV)/bin/python
IMAGE ?= threat-hunting-rag

.PHONY: help install setup api cli cli-interactive query demo-interactive bootstrap env test coverage index qa docker-build docker-up docker-cli docker-api docker-down docker-logs docker-shell docker-test clean rebuild-index full-reset env-%

help:
	@echo "Targets:"
	@echo "  install      Install dependencies"
	@echo "  setup        Initialize data / environment"
	@echo "  generate-dataset  Generate synthetic email dataset (data/emails.csv)"
	@echo "  api          Run API server"
	@echo "  cli          Run CLI interface"
	@echo "  cli-interactive Full interactive CLI (src.interfaces.cli.app)"
	@echo "  query        Prompt for one query"
	@echo "  demo-interactive Run automated interactive CLI session with example queries"
	@echo "  bootstrap    Create venv, install deps, build index"
	@echo "  quick-api    One-step: ensure venv + deps + dataset then start API"
	@echo "  quick-cli    One-step: ensure venv + deps + dataset then start interactive CLI"
	@echo "  env          Create .env from .env.example (FORCE=1 to overwrite)"
	@echo "  docker-build Build Docker image"
	@echo "  docker-up    Start containers with docker-compose (CLI interactive mode)"
	@echo "  docker-cli   Run interactive CLI in Docker"
	@echo "  docker-api   Run API server in Docker"
	@echo "  docker-down  Stop and remove containers"
	@echo "  docker-logs  View container logs"
	@echo "  docker-shell Access container shell"
	@echo "  docker-test  Test API inside container"
	@echo "  test         Run test suite (quick)"
	@echo "  coverage     Run tests with coverage report"
	@echo "  clean        Safe repository cleanup (caches, logs, temp artifacts)"
	@echo "  rebuild-index Regenerate dataset (if missing) and rebuild Chroma index"
	@echo "  full-reset   Clean caches + remove index, regenerate dataset & validate schema, rebuild index"

install:
	$(PYTHON) -m pip install -r requirements.txt

setup:
	$(PYTHON) app.py --setup

api:
	$(PYTHON) app.py --api

cli:
	$(PYTHON) app.py --cli

cli-interactive:
	$(PYTHON) -m src.interfaces.cli.app --interactive

query:
	@read -p "Query: " q; $(PYTHON) app.py --query "$$q"

demo-interactive:
	$(PYTHON) examples/run_interactive_queries.py

bootstrap:
	@if [ ! -d $(VENV) ]; then echo "[bootstrap] Creating venv $(VENV)"; python -m venv $(VENV); fi
	@echo "[bootstrap] Installing dependencies"; $(VENV_PY) -m pip install --upgrade pip >/dev/null 2>&1 || true; $(VENV_PY) -m pip install -r requirements.txt
	@echo "[bootstrap] Building index (regenerate + validate)"; $(VENV_PY) scripts/regenerate_all.py || true
	@echo "[bootstrap] Done. Activate with: source $(VENV)/bin/activate"

env:
	@if [ ! -f .env ] || [ "$(FORCE)" = "1" ]; then cp .env.example .env && echo "[env] .env created"; else echo "[env] .env already exists (use FORCE=1 to overwrite)"; fi


test:
	@bash -c "source $(VENV)/bin/activate && pytest -q"

coverage:
	@bash -c "source $(VENV)/bin/activate && pytest --cov=src --cov-report=term-missing"

env-%:  ## Print value of an environment variable, e.g. `make env-PYTHONPATH`
	@echo "$*=$(${*})"

clean:
	@echo "[clean] Running cleanup script"
	bash scripts/clean_repo.sh
	@echo "[clean] Done"

rebuild-index:
	@echo "[rebuild-index] Rebuilding semantic index (will generate dataset if missing)"
	$(PYTHON) scripts/rebuild_index.py
	@echo "[rebuild-index] Complete"

full-reset:
	@echo "[full-reset] Cleaning repository (including index)"
	bash scripts/clean_repo.sh --with-index
	@echo "[full-reset] Regenerating dataset + validating schema + rebuilding index"
	$(PYTHON) scripts/regenerate_all.py
	@echo "[full-reset] Done"

generate-dataset dataset:
	@echo "[generate-dataset] Generating synthetic email dataset -> data/emails.csv"
	$(PYTHON) src/data_preparation/generators/generate_dataset.py >/dev/null 2>&1 || true
	@echo "[generate-dataset] Complete (see data/emails.csv)"

quick-api:
	@echo "[quick-api] Ensuring virtual environment"
	@if [ ! -d $(VENV) ]; then python -m venv $(VENV); fi
	@echo "[quick-api] Installing dependencies (idempotent)"
	@$(VENV_PY) -m pip install -r requirements.txt >/dev/null 2>&1 || true
	@echo "[quick-api] Checking dataset/index"
	@if [ ! -f data/emails.csv ]; then echo "[quick-api] Dataset missing -> running setup"; $(VENV_PY) app.py --setup; else echo "[quick-api] Dataset present"; fi
	@echo "[quick-api] Starting API server"
	$(VENV_PY) app.py --api

quick-cli:
	@echo "[quick-cli] Ensuring virtual environment"
	@if [ ! -d $(VENV) ]; then python -m venv $(VENV); fi
	@echo "[quick-cli] Installing dependencies (idempotent)"
	@$(VENV_PY) -m pip install -r requirements.txt >/dev/null 2>&1 || true
	@echo "[quick-cli] Checking dataset/index"
	@if [ ! -f data/emails.csv ]; then echo "[quick-cli] Dataset missing -> running setup"; $(VENV_PY) app.py --setup; else echo "[quick-cli] Dataset present"; fi
	@echo "[quick-cli] Launching interactive CLI"
	$(VENV_PY) -m src.interfaces.cli.app --interactive

## Docker targets
docker-build:
	@echo "[docker-build] Building Docker image: $(IMAGE)"
	docker build -t $(IMAGE) .
	@echo "[docker-build] Image built successfully"

docker-up:
	@echo "[docker-up] Starting interactive CLI container"
	docker-compose up
	@echo "[docker-up] Container stopped"

docker-cli:
	@echo "[docker-cli] Running interactive CLI in Docker"
	docker run -it --rm \
		-v $(PWD)/data:/app/data \
		-v $(PWD)/cache:/app/cache \
		-v $(PWD)/logs:/app/logs \
		--env-file .env \
		$(IMAGE)

docker-api:
	@echo "[docker-api] Starting API server in Docker"
	docker run -d --name threat-hunting-rag-api \
		-p 8000:8000 \
		-v $(PWD)/data:/app/data \
		-v $(PWD)/cache:/app/cache \
		-v $(PWD)/logs:/app/logs \
		-e MODE=api \
		-e HOST=0.0.0.0 \
		-e PORT=8000 \
		--env-file .env \
		$(IMAGE)
	@echo "[docker-api] API server started at http://localhost:8000"
	@echo "[docker-api] View logs: docker logs -f threat-hunting-rag-api"
	@echo "[docker-api] Stop with: docker stop threat-hunting-rag-api && docker rm threat-hunting-rag-api"

docker-down:
	@echo "[docker-down] Stopping containers"
	docker-compose down
	@echo "[docker-down] Containers stopped"

docker-logs:
	@echo "[docker-logs] Tailing container logs (Ctrl+C to exit)"
	docker-compose logs -f

docker-shell:
	@echo "[docker-shell] Accessing container shell"
	docker exec -it threat-hunting-rag bash

docker-test:
	@echo "[docker-test] Testing API inside container"
	@echo "Health check:"
	@curl -s http://localhost:8000/health | jq . || curl -s http://localhost:8000/health
	@echo ""
	@echo "Search test:"
	@curl -s -X POST http://localhost:8000/api/v1/search \
		-H "Content-Type: application/json" \
		-d '{"query": "wire transfer from CEO", "top_k": 3}' | jq '.results[0] // .' || echo "Search failed"

docker-restart: docker-down docker-up

docker-clean:
	@echo "[docker-clean] Removing containers and images"
	docker-compose down -v
	docker rmi $(IMAGE) || true
	@echo "[docker-clean] Done"
