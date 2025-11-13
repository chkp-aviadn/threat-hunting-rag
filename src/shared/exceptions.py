"""
Custom exceptions for the threat hunting system.

Domain-specific exceptions that provide clear error handling across all layers.
"""


class ThreatHuntingError(Exception):
    """Base exception for threat hunting system."""

    pass


class ConfigurationError(ThreatHuntingError):
    """Configuration or environment setup errors."""

    pass


class DataError(ThreatHuntingError):
    """Data processing and validation errors."""

    pass


class SearchError(ThreatHuntingError):
    """Search and retrieval errors."""

    pass


class EmbeddingError(ThreatHuntingError):
    """Embedding generation and vector processing errors."""

    pass


class ScoringError(ThreatHuntingError):
    """Threat scoring and analysis errors."""

    pass


class ValidationError(ThreatHuntingError):
    """Input validation errors."""

    pass
