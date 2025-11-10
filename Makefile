# Threat Hunting RAG System - Quality Automation

.PHONY: help install dev-install format lint type-check test security quality clean

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install:  ## Install production dependencies
	pip install -r requirements.txt

dev-install: install  ## Install development dependencies
	pip install pre-commit
	pre-commit install

format:  ## Format code with black
	black src/ tests/
	@echo "✅ Code formatted"

lint:  ## Run flake8 linting
	flake8 src/ tests/
	@echo "✅ Linting passed"

type-check:  ## Run mypy type checking
	mypy src/
	@echo "✅ Type checking passed"

test:  ## Run pytest with coverage
	pytest --cov=src --cov-report=term-missing
	@echo "✅ Tests completed"

security:  ## Run bandit security scan
	bandit -r src/ -f json -o security_report.json
	bandit -r src/
	@echo "✅ Security scan completed"

quality: format lint type-check  ## Run all quality checks
	@echo "🎉 All quality checks passed!"

test-full: quality test security  ## Run complete test suite
	@echo "🚀 Full test suite completed!"

clean:  ## Clean up cache and temporary files
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*~" -delete
	rm -rf .coverage htmlcov/ .pytest_cache/ .mypy_cache/
	@echo "🧹 Cleanup completed"

# Development workflow
dev-setup: dev-install  ## Complete development setup
	@echo "🔧 Development environment ready!"

check: quality test  ## Quick development checks (no security scan)
	@echo "✅ Development checks passed!"
