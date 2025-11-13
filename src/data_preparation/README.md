# 📊 Data Preparation - Task.txt Requirement 1

## 🎯 Overview
This module handles **synthetic email generation** and **embeddings creation** for the threat hunting RAG system. It implements the core data preparation requirements from task.txt.

## 📋 Task.txt Requirements Covered
- ✅ Generate synthetic dataset of 100+ emails using Faker library
- ✅ Include mix of legitimate and phishing emails  
- ✅ Extract and structure relevant metadata (sender, subject, body, timestamps)
- ✅ Generate embeddings for semantic search

## 🏗️ Components

### `generators/`
**Purpose**: Synthetic email generation using Faker library
- `generate_dataset.py`: Main email generation script
  - Creates 150+ realistic emails (70% legitimate, 30% phishing)
  - Uses Faker for realistic content generation
  - Implements phishing patterns and threat indicators
  - Outputs structured CSV dataset

### `embeddings/`  
**Purpose**: Semantic search preparation and vector indexing
- `embeddings.py`: Sentence transformer implementation
  - Uses sentence-transformers/all-MiniLM-L6-v2 model
  - Converts email content to 384-dimension vectors
  - Handles batch processing for efficiency
- `index_builder.py`: Vector database construction
  - Creates Chroma vector database
  - Persists embeddings for fast retrieval
  - Implements similarity search capabilities

### `schemas/`
**Purpose**: Data models and validation schemas  
- `email.py`: Core email data model
  - Pydantic models for email structure
  - Validation for sender, subject, body, timestamps
  - Attachment handling and metadata
  - Integration with threat analysis features

## 🔧 Usage Examples

### Generate Synthetic Dataset
```python
from data_preparation.generators.generate_dataset import generate_emails
emails = generate_emails(count=150)
```

### Create Embeddings
```python  
from data_preparation.embeddings.embeddings import EmbeddingService
service = EmbeddingService()
embeddings = service.generate_embeddings(emails)
```

### Build Vector Index
```python
from data_preparation.embeddings.index_builder import IndexBuilder
builder = IndexBuilder()
index = builder.build_index(emails, embeddings)
```

## 📊 Data Flow
```
Faker Library → Email Generation → Structured Dataset → Embeddings → Vector Index
```

## ✅ Deliverables
1. **Synthetic Dataset**: `data/emails.csv` (150+ emails)
2. **Vector Index**: Persistent Chroma database at `data/chroma/`  
3. **Embeddings**: 384-dimensional semantic vectors
4. **Validation**: Structured email models with type safety

## 🎯 Quality Metrics
- **Dataset Size**: 150+ emails (exceeds 100+ requirement)
- **Class Balance**: 70% legitimate, 30% phishing  
- **Realism**: Faker-generated realistic content
- **Embeddings**: sentence-transformers quality vectors
- **Performance**: Batch processing for efficiency