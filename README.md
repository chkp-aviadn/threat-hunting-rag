# 🛡️ Threat Hunting RAG System

A Retrieval-Augmented Generation (RAG) system for **phishing threat hunting** that analyzes email datasets through natural language queries and returns ranked, explainable threat detections.

## 🎯 Overview

This system processes natural language queries like *"Show me emails with urgent payment requests from new senders"* and combines keyword and semantic search for comprehensive threat detection with confidence scores and human-readable explanations.

## 🚀 Quick Start

```bash
# Setup environment
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Generate dataset and build index
python src/generate_dataset.py
python src/index_builder.py

# Start API server
uvicorn src.api:app --reload --port 8000

# Or use CLI for development
python src/cli.py --query "urgent payment requests"
```

## 📚 Documentation

- [Implementation Plan](../plan.md) - Complete development roadmap
- [API Documentation](http://localhost:8000/docs) - Interactive Swagger UI
- [Example Queries](src/examples/queries_examples.md) - Sample usage

## 🏗️ Architecture

See [Architecture Diagram](diagrams/architecture.mmd) for system design.

## ✅ Status

🔄 **In Development** - Following implementation plan step by step.

**Current Phase:** Task 1.1 - Project Structure Initialization ✅

**Next:** Task 1.2 - Dependencies & Configuration
