"""
Port interfaces for the core domain.

Defines contracts that external layers must implement to interact with core business logic.
"""

from .repositories import EmailRepository, VectorRepository
from .services import (
    EmbeddingService,
    FeatureExtractor, 
    ThreatScorer,
    SearchService,
    ExplanationService
)

__all__ = [
    # Repository ports
    "EmailRepository",
    "VectorRepository",
    
    # Service ports  
    "EmbeddingService",
    "FeatureExtractor",
    "ThreatScorer", 
    "SearchService",
    "ExplanationService"
]
