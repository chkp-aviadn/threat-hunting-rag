#!/bin/bash
# Threat Hunting RAG System - Startup Script

set -e

echo "=========================================="
echo "Threat Hunting RAG System - Starting"
echo "=========================================="

# Create necessary directories
mkdir -p /app/data /app/cache /app/logs

# Setup system if needed
echo "Checking system status..."
python app.py --validate || {
    echo "System validation failed. Running setup..."
    python app.py --setup
}

# Start the application based on MODE environment variable
MODE=${MODE:-cli-interactive}

case "$MODE" in
    api)
        echo "Starting API server..."
        python app.py --api
        ;;
    cli)
        echo "Starting CLI interface..."
        python app.py --cli
        ;;
    cli-interactive)
        echo "Starting interactive CLI..."
        python -m src.interfaces.cli.app --interactive
        ;;
    setup)
        echo "Running setup only..."
        python app.py --setup
        ;;
    *)
        echo "Unknown MODE: $MODE"
        echo "Valid options: api, cli, cli-interactive, setup"
        exit 1
        ;;
esac
