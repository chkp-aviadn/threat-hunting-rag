# Dockerfile for Threat Hunting RAG System
# Provides clean environment with pre-built ML dependencies

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    software-properties-common \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
# Use --no-cache-dir to reduce image size
# Install torch CPU-only version first to avoid CUDA issues
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p logs data cache src/infrastructure/cache/models src/infrastructure/cache/embeddings

# Set environment variables
ENV PYTHONPATH=/app/src
ENV LOG_LEVEL=INFO
ENV MODEL_CACHE_DIR=/app/cache/models
ENV EMBEDDING_CACHE_DIR=/app/cache/embeddings

# Expose port for API (future use)
EXPOSE 8000

# Default command
CMD ["python", "main.py"]