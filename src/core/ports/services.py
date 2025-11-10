"""
Service interfaces for business operations.

Defines contracts for services that implement core business logic.
"""

from abc import ABC, abstractmethod
from typing import List

from core.models import Email, ThreatFeatures, SearchQuery, SearchResults


class EmbeddingService(ABC):
    """Abstract service for generating embeddings."""
    
    @abstractmethod
    def embed_text(self, text: str) -> List[float]:
        """Generate embedding for text."""
        pass
    
    @abstractmethod
    def embed_email(self, email: Email) -> List[float]:
        """Generate embedding for email content."""
        pass
    
    @abstractmethod
    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings for multiple texts efficiently."""
        pass


class FeatureExtractor(ABC):
    """Abstract service for extracting threat features."""
    
    @abstractmethod
    def extract_features(self, email: Email) -> ThreatFeatures:
        """Extract threat features from email."""
        pass
    
    @abstractmethod
    def extract_batch(self, emails: List[Email]) -> List[ThreatFeatures]:
        """Extract features from multiple emails efficiently."""
        pass


class ThreatScorer(ABC):
    """Abstract service for calculating threat scores."""
    
    @abstractmethod
    def calculate_score(self, features: ThreatFeatures) -> float:
        """Calculate threat score from features."""
        pass
    
    @abstractmethod
    def calculate_confidence(self, features: ThreatFeatures) -> float:
        """Calculate confidence in the threat score."""
        pass


class SearchService(ABC):
    """Abstract service for search operations."""
    
    @abstractmethod
    def search(self, query: SearchQuery) -> SearchResults:
        """Perform search and return ranked results."""
        pass
    
    @abstractmethod
    def keyword_search(self, query_text: str, limit: int) -> List[Email]:
        """Perform keyword-based search."""
        pass
    
    @abstractmethod
    def semantic_search(self, query_text: str, limit: int) -> List[Email]:
        """Perform semantic search using embeddings."""
        pass


class ExplanationService(ABC):
    """Abstract service for generating explanations."""
    
    @abstractmethod
    def explain_threat(self, email: Email, features: ThreatFeatures) -> str:
        """Generate human-readable explanation for threat detection."""
        pass
    
    @abstractmethod
    def explain_search_relevance(self, email: Email, query: SearchQuery, score: float) -> str:
        """Explain why email matched the search query."""
        pass
