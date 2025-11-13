# 🔍 Query Processing - Task.txt Requirement 2

## 🎯 Overview  
This module implements **intelligent natural language query processing** with hybrid search capabilities. It handles the core query understanding and retrieval requirements from task.txt.

## 📋 Task.txt Requirements Covered
- ✅ Support natural language queries like "Show me emails with urgent payment requests from new senders"
- ✅ Implement both keyword and semantic search capabilities
- ✅ Handle example queries: urgent payments, suspicious attachments, executive impersonation
- ✅ Return ranked results with relevance scoring

## 🏗️ Components

### `parsers/`
**Purpose**: Natural language query understanding and intent classification
- `query_parser.py`: Query preprocessing and normalization
  - Extracts key terms and phrases from natural language
  - Identifies search intent (urgent, suspicious, executive, etc.)
  - Handles query expansion and synonym mapping
- `intent_classifier.py`: Query categorization
  - Classifies queries into threat categories
  - Maps to appropriate search strategies
  - Handles multi-intent queries

### `retrieval/`
**Purpose**: Hybrid search implementation (keyword + semantic)
- `retrieval.py`: Main retrieval orchestrator
  - Coordinates keyword and semantic search
  - Implements result fusion and ranking
  - Handles query routing and optimization
- `retriever.py`: Core search implementations
  - BM25 keyword search for exact matches
  - Vector similarity for semantic search  
  - Hybrid scoring algorithms

### `models/`
**Purpose**: Query and search result data models
- `search.py`: Search query and result structures
  - SearchQuery: Query representation with metadata
  - SearchResults: Ranked result containers
  - QueryResult: Individual result with scoring

## 🔧 Usage Examples

### Natural Language Query Processing
```python  
from query_processing.parsers.query_parser import QueryParser
parser = QueryParser()
processed = parser.parse("Show me urgent payment requests from new senders")
```

### Keyword Search
```python
from query_processing.retrieval.retrieval import KeywordRetriever
retriever = KeywordRetriever()
results = retriever.search("urgent payment requests")
```

### Semantic Search  
```python
from query_processing.retrieval.retrieval import SemanticRetriever
retriever = SemanticRetriever()
results = retriever.search("suspicious email attachments")
```

### Hybrid Search (Recommended)
```python
from query_processing.retrieval.retrieval import HybridRetriever
retriever = HybridRetriever()
results = retriever.search("executive impersonation emails")
```

## 📊 Search Methods

### 1. **Keyword Search** (Exact Matching)
- BM25 algorithm for term matching
- Regex patterns for specific indicators  
- Fast exact phrase matching
- **Use Case**: Precise term searches

### 2. **Semantic Search** (Contextual Understanding)
- Vector similarity using embeddings
- Handles synonyms and context
- Cross-language understanding
- **Use Case**: Natural language queries

### 3. **Hybrid Search** (Best of Both) ⭐
- Combines keyword + semantic results
- Weighted scoring and fusion
- Deduplication and ranking
- **Use Case**: Production queries (default)

## 🎯 Example Query Coverage

### Supported Query Types
```
✅ "Show me emails with urgent payment requests from new senders"
✅ "Find emails with suspicious attachment names"  
✅ "Identify emails that impersonate executives"
✅ "List emails requesting wire transfers within 24 hours"
✅ "Find emails with reset password links"
✅ "Emails mentioning final notice or account suspension"
✅ "Attachments with invoice or salary info"
✅ "Mentions of gift cards or crypto payments"  
✅ "Domains similar to company domain"
✅ "Emails sent outside business hours requesting payment"
```

## 📊 Performance Metrics
- **Response Time**: <2 seconds (task.txt requirement)
- **Relevance**: Ranked results with confidence scores
- **Recall**: Comprehensive result coverage
- **Precision**: Accurate result filtering

## 🔄 Data Flow
```
Natural Language Query → Query Parser → Intent Classification → 
Keyword Search ↘
                 → Result Fusion → Ranked Results
Semantic Search ↗
```