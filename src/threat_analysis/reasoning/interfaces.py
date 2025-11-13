"""
Business service interfaces for core logic.

Defines abstract base classes for implemented business services.
Only includes interfaces that are actually used by the system.
"""

from abc import ABC, abstractmethod
from typing import List
import sys
import os

# Add src to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from data_preparation.schemas.email import Email
from threat_analysis.models.threat import ThreatFeatures
from query_processing.models.search import SearchQuery, SearchResults


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
