# Docker Deployment Guide

Simple Docker setup for the Threat Hunting RAG System.

## Quick Start

### 1. Build and Run with Docker Compose (Recommended)

```bash
# Build the image
docker-compose build

# Start the service
docker-compose up -d

# View logs
docker-compose logs -f

# Check status
curl http://localhost:8000/health
```

### 2. Build and Run with Docker CLI

```bash
# Build the image
docker build -t threat-hunting-rag .

# Run the container
docker run -d \
  --name threat-hunting-rag \
  -p 8000:8000 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/cache:/app/cache \
  -v $(pwd)/logs:/app/logs \
  --env-file .env \
  threat-hunting-rag

# View logs
docker logs -f threat-hunting-rag
```

## Configuration

### Environment Variables

Copy `.env.example` to `.env` and adjust:

```bash
cp .env.example .env
```

Key variables:
- `PORT`: API port (default: 8000)
- `HOST`: Bind address (default: 0.0.0.0 in Docker)
- `LOG_LEVEL`: Logging level (INFO, DEBUG, WARNING)
- `CHROMA_TELEMETRY_DISABLED`: Disable ChromaDB telemetry (TRUE)

### Run Modes

Change the startup mode via environment variable:

```bash
# API mode (default)
docker run -e MODE=api threat-hunting-rag

# CLI mode
docker run -it -e MODE=cli threat-hunting-rag

# Setup only
docker run -e MODE=setup threat-hunting-rag
```

## Data Persistence

The following directories are mounted as volumes:
- `./data` - Email dataset and ChromaDB vector index
- `./cache` - Embeddings and model cache
- `./logs` - Application logs

## Health Check

The container includes a health check:

```bash
# Check container health
docker ps

# Manual health check
curl http://localhost:8000/health
```

## Useful Commands

```bash
# Stop the service
docker-compose down

# Rebuild after code changes
docker-compose up --build -d

# View resource usage
docker stats threat-hunting-rag

# Execute commands inside container
docker exec -it threat-hunting-rag python app.py --validate

# Access container shell
docker exec -it threat-hunting-rag bash

# Remove container and volumes
docker-compose down -v
```

## Testing the API

```bash
# Search for threats
curl -X POST http://localhost:8000/api/v1/search \
  -H "Content-Type: application/json" \
  -d '{"query": "wire transfer from CEO", "top_k": 5}'

# Chat interface
curl -X POST http://localhost:8000/api/v1/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Show me suspicious wire transfers", "session_id": "test-session"}'
```

## Troubleshooting

### Container won't start
```bash
# Check logs
docker logs threat-hunting-rag

# Validate setup
docker exec -it threat-hunting-rag python app.py --validate
```

### Port already in use
```bash
# Change port in docker-compose.yml or use different port:
docker-compose run -p 8001:8000 threat-hunting-rag
```

### Dataset not found
```bash
# Run setup inside container
docker exec -it threat-hunting-rag python app.py --setup
```

## Production Considerations

1. **Security**: Change default API keys in `.env`
2. **Resources**: Adjust container limits in `docker-compose.yml`
3. **Persistence**: Use named volumes for production
4. **Monitoring**: Integrate with logging solutions (ELK, Grafana)
5. **Scaling**: Use orchestration (Kubernetes, Docker Swarm)

## Optional: Redis Cache

Uncomment the Redis service in `docker-compose.yml` and update `.env`:

```bash
REDIS_ENABLED=true
REDIS_URL=redis://redis:6379/0
```

Then restart:
```bash
docker-compose up -d
```
