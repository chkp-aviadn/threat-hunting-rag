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
python -m infrastructure.data.generate_dataset
python -m infrastructure.ml.index_builder

# Start API server
uvicorn interfaces.api.app:app --reload --port 8000

# Or use CLI for development  
python -m interfaces.cli.app --query "urgent payment requests"
```

## 📚 Documentation

- [Implementation Plan](plan.md) - Complete development roadmap  
- [API Documentation](http://localhost:8000/docs) - Interactive Swagger UI
- [Example Queries](examples/queries_examples.md) - Sample usage
- [Architecture Diagrams](diagrams/) - System design and flow

## 🏗️ Clean Modular Architecture

```
src/
├── 🧠 core/              # Business Logic (Framework-independent)
│   ├── models/          # Domain entities (Email, ThreatFeatures)
│   ├── ports/           # Interface contracts
│   └── services/        # Business services
├── 🔧 infrastructure/   # External Dependencies  
│   ├── data/           # Data generation
│   ├── ml/             # ML models & vector DB
│   └── cache/          # Performance caches
├── 🌐 interfaces/      # User Interfaces
│   ├── api/            # REST API
│   └── cli/            # Command line
└── 🔄 shared/          # Common utilities
```

## ✅ Status

✅ **Architecture Completed** - Clean modular design implemented

**Completed:** Clean Architecture with Domain-Driven Design
- Core domain models with business logic
- Port/Adapter pattern for infrastructure  
- Separation of concerns across layers
- Professional, maintainable, and testable codebase

**Next:** Implement infrastructure and service layers
