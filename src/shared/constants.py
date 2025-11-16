"""Centralized constants for thresholds, weights, and configuration knobs.

Purpose: Reduce magic numbers scattered across pipeline, scoring, and explanation logic.
"""

from typing import Dict

# Threat level score thresholds (overall threat_score)
THREAT_LEVEL_THRESHOLDS = {
    "CRITICAL": 0.75,
    "HIGH": 0.60,
    "MEDIUM": 0.40,
    "LOW": 0.15,
    "NEGLIGIBLE": 0.0,
}

# Feature weighting for aggregated risk scoring (ThreatFeatures.get_overall_score)
AGGREGATED_FEATURE_WEIGHTS: Dict[str, float] = {
    "urgent_language": 0.12,
    "suspicious_language": 0.08,
    "executive_impersonation": 0.25,
    "new_sender": 0.08,
    "domain_suspicious": 0.12,
    "suspicious_attachment": 0.15,
    "executable_attachment": 0.30,
    "financial_request": 0.15,
    "credential_harvest": 0.20,
    "link_suspicious": 0.10,
    "outside_hours": 0.05,
}

# Primary ThreatScorer feature weights (must sum to 1.0)
THREAT_SCORER_WEIGHTS: Dict[str, float] = {
    "urgent_language": 0.25,
    "suspicious_attachment": 0.35,
    "executive_impersonation": 0.30,
    "new_sender": 0.10,
}

# Explanation indicator thresholds
EXPLANATION_DETAILED_THRESHOLD = 0.4
EXPLANATION_COMPACT_THRESHOLD = 0.6
EXPLANATION_COMPACT_MAX_INDICATORS = 3

# Similarity normalization safety (min denominator)
SIMILARITY_MIN_DENOMINATOR = 1e-9

# Confidence calculation parameters (for ThreatScorer and pipeline blend logic)
CONFIDENCE_FEATURE_BONUS = 0.15  # per detected high-confidence feature (pipeline)
CONFIDENCE_DIVERSITY_MAX_BONUS = 0.2  # scorer diversity cap
CONFIDENCE_WEAK_PENALTY = 0.1  # penalty per weak signal (<0.5)

# Threat score blending ratios (pipeline enhancement)
BLEND_WEIGHT_SCORER = 0.7
BLEND_WEIGHT_ORIGINAL = 0.3

__all__ = [
    "THREAT_LEVEL_THRESHOLDS",
    "AGGREGATED_FEATURE_WEIGHTS",
    "THREAT_SCORER_WEIGHTS",
    "EXPLANATION_DETAILED_THRESHOLD",
    "EXPLANATION_COMPACT_THRESHOLD",
    "EXPLANATION_COMPACT_MAX_INDICATORS",
    "SIMILARITY_MIN_DENOMINATOR",
    "CONFIDENCE_FEATURE_BONUS",
    "CONFIDENCE_DIVERSITY_MAX_BONUS",
    "CONFIDENCE_WEAK_PENALTY",
    "BLEND_WEIGHT_SCORER",
    "BLEND_WEIGHT_ORIGINAL",
]
