"""
Core business logic layer.

Contains domain models, business services, and interface contracts (ports).
This layer is independent of infrastructure and external frameworks.
"""

from .models import Email, ThreatFeatures, SearchQuery, SearchResults
from .ports import (
    EmailRepository, 
    VectorRepository,
    EmbeddingService,
    FeatureExtractor,
    ThreatScorer, 
    SearchService,
    ExplanationService
)

__all__ = [
    # Domain models
    "Email",
    "ThreatFeatures", 
    "SearchQuery",
    "SearchResults",
    
    # Port interfaces
    "EmailRepository",
    "VectorRepository", 
    "EmbeddingService",
    "FeatureExtractor",
    "ThreatScorer",
    "SearchService", 
    "ExplanationService"
]
