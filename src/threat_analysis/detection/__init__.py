"""
Threat Analysis Domain

This module contains all services related to threat detection and analysis:
- Feature extraction from emails
- Threat scoring and risk assessment
- Domain validation and analysis
"""

from .features import FeatureExtractor, FeatureResult
from .scorer import ThreatScorer, ThreatScore
from .domain_validator import EnhancedDomainAnalyzer, DomainValidationResult

__all__ = [
    "FeatureExtractor",
    "FeatureResult",
    "ThreatScorer",
    "ThreatScore",
    "EnhancedDomainAnalyzer",
    "DomainValidationResult",
]
