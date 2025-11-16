# Threat Hunting RAG System - Docker Image
# Base Image: Python 3.11
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip and setuptools
RUN pip install --upgrade pip setuptools

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt

# Copy application code (excluding data, cache, logs - those will be mounted as volumes)
COPY app.py .
COPY pyproject.toml .
COPY pytest.ini .
COPY Makefile .
COPY src/ ./src/
COPY tests/ ./tests/
COPY examples/ ./examples/
COPY scripts/ ./scripts/

# Create necessary directories (will be mounted as volumes at runtime)
RUN mkdir -p /app/data /app/cache /app/logs

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV CHROMA_TELEMETRY_DISABLED=TRUE
ENV ANONYMIZED_TELEMETRY=FALSE

# Expose API port
EXPOSE 8000

# Health check (disabled for CLI mode)
# HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
#     CMD curl -f http://localhost:8000/health || exit 1

# Default command: Start interactive CLI
CMD ["python", "-m", "src.interfaces.cli.app", "--interactive"]
