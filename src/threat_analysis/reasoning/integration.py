"""
Integration utilities for explanation generation across the threat hunting system.

Provides factory methods and integration helpers to connect the new
explanation generation service with existing threat analysis components.
"""

import logging
from typing import Optional

from data_preparation.schemas.email import Email
from threat_analysis.models.threat import ThreatFeatures
from query_processing.models.search import SearchQuery
from threat_analysis.reasoning.explainer import RuleBasedExplainer, EnhancedExplainer

logger = logging.getLogger(__name__)


class ExplanationFactory:
    """Factory for creating and managing explanation services."""

    _instance: Optional["ExplanationFactory"] = None
    _explainer: Optional[RuleBasedExplainer] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    @classmethod
    def get_explainer(cls, enhanced: bool = False) -> RuleBasedExplainer:
        """
        Get explanation service instance.

        Args:
            enhanced: Whether to use enhanced explainer with LLM (if available)

        Returns:
            Explanation service instance
        """
        if cls._explainer is None:
            if enhanced:
                cls._explainer = EnhancedExplainer()
                logger.info("Created enhanced explainer service")
            else:
                cls._explainer = RuleBasedExplainer()
                logger.info("Created rule-based explainer service")

        return cls._explainer

    @classmethod
    def explain_threat_features(cls, email: Email, features: ThreatFeatures) -> str:
        """
        Convenience method to generate threat explanation.

        Args:
            email: The email being analyzed
            features: Extracted threat features

        Returns:
            Human-readable threat explanation
        """
        explainer = cls.get_explainer()
        return explainer.explain_threat(email, features)

    @classmethod
    def explain_search_match(cls, email: Email, query: SearchQuery, score: float) -> str:
        """
        Convenience method to explain search relevance.

        Args:
            email: The matching email
            query: The search query
            score: Relevance score

        Returns:
            Search relevance explanation
        """
        explainer = cls.get_explainer()
        return explainer.explain_search_relevance(email, query, score)


def generate_threat_explanation(email: Email, features: ThreatFeatures) -> str:
    """
    Generate threat explanation using the configured explainer.

    This is a simple function interface for backward compatibility
    with existing code that expects a function call.

    Args:
        email: The email being analyzed
        features: Extracted threat features

    Returns:
        Human-readable explanation
    """
    return ExplanationFactory.explain_threat_features(email, features)


def generate_search_explanation(email: Email, query: SearchQuery, score: float) -> str:
    """
    Generate search relevance explanation.

    Args:
        email: The matching email
        query: The search query
        score: Relevance score

    Returns:
        Search relevance explanation
    """
    return ExplanationFactory.explain_search_match(email, query, score)
