"""
Threat scoring system for phishing risk assessment (Task 5.2).

This module implements weighted aggregation of threat features to calculate
overall phishing likelihood scores with confidence levels and ranking.

Key Features:
    - Configurable weighted scoring algorithm
    - Confidence calculation and normalization
    - Threat level categorization (LOW, MEDIUM, HIGH, CRITICAL)
    - Result ranking and filtering
    - Integration with feature extraction system
"""

import logging
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
import math
import sys
import os

# Add src to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))

from data_preparation.schemas.email import Email
from threat_analysis.models.threat import ThreatFeatures
from .features import FeatureExtractor, FeatureResult
from shared.enums import ThreatLevel
from shared.constants import THREAT_SCORER_WEIGHTS, THREAT_LEVEL_THRESHOLDS

# Set up logging
logger = logging.getLogger(__name__)


@dataclass
class ThreatScore:
    """Comprehensive threat scoring result."""

    email_id: str
    overall_score: float  # 0.0 to 1.0
    confidence: float  # 0.0 to 1.0
    threat_level: ThreatLevel
    feature_scores: Dict[str, float]
    risk_factors: List[str]
    explanation: str


class ThreatScorer:
    """
    Weighted threat scoring system for phishing risk assessment.

    PERFORMANCE: ~2ms per email for complete threat scoring.
    WHY: Combines multiple threat signals into single actionable score
    for threat hunters to prioritize investigation efforts.
    """

    def __init__(self, custom_weights: Optional[Dict[str, float]] = None):
        """
        Initialize threat scorer with configurable weights.

        Args:
            custom_weights: Optional custom feature weights (must sum to 1.0)
        """
        # Default weights from plan.md Task 5.2 requirements
        self.default_weights = THREAT_SCORER_WEIGHTS

        # Use custom weights if provided, otherwise defaults
        if custom_weights:
            self._validate_weights(custom_weights)
            self.weights = custom_weights
        else:
            self.weights = self.default_weights

        # Initialize feature extractor
        self.feature_extractor = FeatureExtractor()

        # Threat level thresholds
        self.threat_thresholds = {
            ThreatLevel.LOW: THREAT_LEVEL_THRESHOLDS["LOW"],
            ThreatLevel.MEDIUM: 0.3,  # internal scorer medium differs slightly from aggregated thresholds
            ThreatLevel.HIGH: 0.7,
            ThreatLevel.CRITICAL: THREAT_LEVEL_THRESHOLDS["CRITICAL"],
        }

        logger.info(f"ThreatScorer initialized with weights: {self.weights}")

    def calculate_threat_score(self, features: ThreatFeatures) -> float:
        """
        Calculate threat score from ThreatFeatures directly (for testing).

        Args:
            features: ThreatFeatures object with feature scores

        Returns:
            Overall weighted threat score (0.0 to 1.0)
        """
        feature_scores = {
            "urgent_language": features.urgent_language,
            "suspicious_attachment": features.suspicious_attachment,
            "executive_impersonation": features.executive_impersonation,
            "new_sender": features.new_sender,
        }

        # Weighted aggregation using configured weights
        overall_score = sum(
            feature_scores[feature] * self.weights[feature] for feature in self.weights.keys()
        )

        return min(1.0, max(0.0, overall_score))  # Ensure bounds [0,1]

    def score_email(self, email: Email) -> ThreatScore:
        """
        Calculate comprehensive threat score for an email.

        Args:
            email: Email object to score

        Returns:
            ThreatScore with detailed analysis

        Example:
            >>> scorer = ThreatScorer()
            >>> email = Email(subject="URGENT: Wire transfer needed", ...)
            >>> score = scorer.score_email(email)
            >>> score.overall_score > 0.7
            True
            >>> score.threat_level == ThreatLevel.HIGH
            True
        """
        try:
            logger.debug(f"Scoring email {email.id}")

            # Extract all features
            text_content = email.subject + " " + email.body

            # Get individual feature results
            urgent_result = self.feature_extractor.detect_urgent_language(text_content)
            attachment_result = self.feature_extractor.detect_suspicious_attachments(
                email.attachments
            )
            executive_result = self.feature_extractor.detect_executive_impersonation(text_content)
            sender_result = self.feature_extractor.detect_new_sender(email.sender)

            # Calculate weighted score
            feature_scores = {
                "urgent_language": urgent_result.confidence if urgent_result.detected else 0.0,
                "suspicious_attachment": (
                    attachment_result.confidence if attachment_result.detected else 0.0
                ),
                "executive_impersonation": (
                    executive_result.confidence if executive_result.detected else 0.0
                ),
                "new_sender": sender_result.confidence if sender_result.detected else 0.0,
            }

            # Weighted aggregation
            overall_score = sum(
                feature_scores[feature] * self.weights[feature] for feature in self.weights.keys()
            )
            
            # CRITICAL ESCALATION: Executable attachments automatically trigger high scores
            if attachment_result.detected:
                executable_extensions = [".exe", ".scr", ".js", ".vbs", ".bat", ".cmd"]
                has_executable = any(
                    any(ext in indicator.lower() for ext in executable_extensions) 
                    for indicator in attachment_result.indicators
                )
                if has_executable:
                    # Boost score significantly for executable attachments
                    overall_score = max(overall_score, 0.8)  # Ensure at least HIGH/CRITICAL range
                    logger.debug(f"Executable attachment detected - score boosted to {overall_score}")

            # Calculate confidence based on number and strength of signals
            confidence = self._calculate_confidence(
                [urgent_result, attachment_result, executive_result, sender_result]
            )

            # Determine threat level
            threat_level = self._determine_threat_level(overall_score)

            # Collect risk factors
            risk_factors = []
            all_results = [urgent_result, attachment_result, executive_result, sender_result]
            for result in all_results:
                if result.detected:
                    risk_factors.extend(result.indicators[:2])  # Top 2 indicators per feature

            # Generate explanation
            explanation = self._generate_explanation(overall_score, threat_level, all_results)

            threat_score = ThreatScore(
                email_id=email.id,
                overall_score=overall_score,
                confidence=confidence,
                threat_level=threat_level,
                feature_scores=feature_scores,
                risk_factors=risk_factors,
                explanation=explanation,
            )

            logger.debug(f"Email {email.id} scored: {overall_score:.3f} ({threat_level.value})")
            return threat_score

        except Exception as e:
            logger.error(f"Threat scoring failed for email {email.id}: {e}")
            # Return safe low-risk score on error
            return ThreatScore(
                email_id=email.id,
                overall_score=0.0,
                confidence=0.0,
                threat_level=ThreatLevel.LOW,
                feature_scores={},
                risk_factors=[],
                explanation=f"Scoring error: {str(e)}",
            )

    def score_multiple_emails(self, emails: List[Email]) -> List[ThreatScore]:
        """
        Score multiple emails and return sorted results.

        Args:
            emails: List of Email objects to score

        Returns:
            List of ThreatScore objects sorted by overall_score (descending)

        Example:
            >>> scorer = ThreatScorer()
            >>> emails = [email1, email2, email3]
            >>> scores = scorer.score_multiple_emails(emails)
            >>> scores[0].overall_score >= scores[1].overall_score
            True
        """
        scores = []

        for email in emails:
            try:
                score = self.score_email(email)
                scores.append(score)
            except Exception as e:
                logger.error(f"Failed to score email {email.id}: {e}")
                continue

        # Sort by overall score (highest risk first)
        scores.sort(key=lambda x: x.overall_score, reverse=True)

        logger.info(f"Scored {len(scores)} emails, highest risk: {scores[0].overall_score:.3f}")
        return scores

    def filter_by_threshold(self, scores: List[ThreatScore], threshold: float) -> List[ThreatScore]:
        """
        Filter threat scores by minimum threshold.

        Args:
            scores: List of ThreatScore objects
            threshold: Minimum threat score (0.0 to 1.0)

        Returns:
            Filtered list of threat scores above threshold

        Example:
            >>> high_risk = scorer.filter_by_threshold(scores, 0.7)
            >>> all(s.overall_score >= 0.7 for s in high_risk)
            True
        """
        filtered = [score for score in scores if score.overall_score >= threshold]
        logger.debug(f"Filtered {len(filtered)}/{len(scores)} scores above threshold {threshold}")
        return filtered

    def filter_by_threat_level(
        self, scores: List[ThreatScore], min_level: ThreatLevel
    ) -> List[ThreatScore]:
        """
        Filter threat scores by minimum threat level.

        Args:
            scores: List of ThreatScore objects
            min_level: Minimum threat level

        Returns:
            Filtered list of threat scores at or above threat level
        """
        level_order = [ThreatLevel.LOW, ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL]
        min_index = level_order.index(min_level)

        filtered = [score for score in scores if level_order.index(score.threat_level) >= min_index]

        logger.debug(f"Filtered {len(filtered)}/{len(scores)} scores at {min_level.value}+ level")
        return filtered

    def get_scoring_statistics(self, scores: List[ThreatScore]) -> Dict[str, Any]:
        """
        Get comprehensive statistics about threat scoring results.

        Args:
            scores: List of ThreatScore objects

        Returns:
            Dictionary with statistical analysis
        """
        if not scores:
            return {"error": "No scores provided"}

        # Overall score statistics
        overall_scores = [s.overall_score for s in scores]

        # Threat level distribution
        level_counts = {}
        for level in ThreatLevel:
            level_counts[level.value] = sum(1 for s in scores if s.threat_level == level)

        # Feature activation rates
        feature_activation = {}
        for feature in self.weights.keys():
            activated = sum(1 for s in scores if s.feature_scores.get(feature, 0) > 0)
            feature_activation[feature] = activated / len(scores)

        return {
            "total_emails": len(scores),
            "score_statistics": {
                "mean": sum(overall_scores) / len(overall_scores),
                "max": max(overall_scores),
                "min": min(overall_scores),
                "high_risk_count": sum(1 for s in overall_scores if s >= 0.7),
            },
            "threat_level_distribution": level_counts,
            "feature_activation_rates": feature_activation,
            "top_risk_factors": self._get_top_risk_factors(scores),
        }

    def _calculate_confidence(self, feature_results: List[FeatureResult]) -> float:
        """
        Calculate overall confidence based on feature detection strength.

        Args:
            feature_results: List of FeatureResult objects

        Returns:
            Confidence score (0.0 to 1.0)
        """
        detected_features = [r for r in feature_results if r.detected]

        if not detected_features:
            return 0.0

        # Base confidence from average of detected features
        avg_confidence = sum(r.confidence for r in detected_features) / len(detected_features)

        # Boost confidence for multiple independent signals
        signal_diversity_bonus = min(0.2, len(detected_features) * 0.05)

        # Reduce confidence if only weak signals
        weak_signals = sum(1 for r in detected_features if r.confidence < 0.5)
        weak_penalty = weak_signals * 0.1

        final_confidence = min(1.0, avg_confidence + signal_diversity_bonus - weak_penalty)
        return max(0.0, final_confidence)

    def _determine_threat_level(self, score: float) -> ThreatLevel:
        """
        Determine threat level based on overall score.

        Args:
            score: Overall threat score (0.0 to 1.0)

        Returns:
            Corresponding ThreatLevel
        """
        if score >= self.threat_thresholds[ThreatLevel.CRITICAL]:
            return ThreatLevel.CRITICAL
        elif score >= self.threat_thresholds[ThreatLevel.HIGH]:
            return ThreatLevel.HIGH
        elif score >= self.threat_thresholds[ThreatLevel.MEDIUM]:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW

    def _generate_explanation(
        self, score: float, threat_level: ThreatLevel, results: List[FeatureResult]
    ) -> str:
        """
        Generate human-readable explanation of threat score.

        Args:
            score: Overall threat score
            threat_level: Determined threat level
            results: List of feature detection results

        Returns:
            Human-readable explanation string
        """
        detected_results = [r for r in results if r.detected]

        if not detected_results:
            return f"{threat_level.value} risk (score: {score:.3f}) - No threat indicators detected"

        # Build explanation from detected features
        explanations = []
        for result in detected_results:
            if result.confidence >= 0.7:
                explanations.append(f"{result.feature_name} ({result.confidence:.2f})")
            elif result.confidence >= 0.5:
                explanations.append(f"moderate {result.feature_name}")

        if explanations:
            feature_summary = ", ".join(explanations)
            return f"{threat_level.value} risk (score: {score:.3f}) - Detected: {feature_summary}"
        else:
            return f"{threat_level.value} risk (score: {score:.3f}) - {len(detected_results)} weak indicators"

    def _get_top_risk_factors(
        self, scores: List[ThreatScore], top_n: int = 10
    ) -> List[Tuple[str, int]]:
        """Get most common risk factors across all scored emails."""
        risk_factor_counts = {}

        for score in scores:
            for factor in score.risk_factors:
                risk_factor_counts[factor] = risk_factor_counts.get(factor, 0) + 1

        # Sort by frequency and return top N
        sorted_factors = sorted(risk_factor_counts.items(), key=lambda x: x[1], reverse=True)
        return sorted_factors[:top_n]

    def _validate_weights(self, weights: Dict[str, float]) -> None:
        """
        Validate that weights are properly configured.

        Args:
            weights: Dictionary of feature weights

        Raises:
            ValueError: If weights are invalid
        """
        # Check that all required features are present
        required_features = set(self.default_weights.keys())
        provided_features = set(weights.keys())

        if required_features != provided_features:
            missing = required_features - provided_features
            extra = provided_features - required_features
            raise ValueError(f"Weight validation failed. Missing: {missing}, Extra: {extra}")

        # Check that weights sum to 1.0 (within tolerance)
        total_weight = sum(weights.values())
        if abs(total_weight - 1.0) > 0.001:
            raise ValueError(f"Weights must sum to 1.0, got {total_weight}")

        # Check that all weights are positive
        if any(w < 0 for w in weights.values()):
            raise ValueError("All weights must be positive")

        logger.info("Weight validation passed")

    def update_weights(self, new_weights: Dict[str, float]) -> None:
        """
        Update scoring weights with validation.

        Args:
            new_weights: New feature weights

        Raises:
            ValueError: If weights are invalid
        """
        self._validate_weights(new_weights)
        old_weights = self.weights.copy()
        self.weights = new_weights
        logger.info(f"Updated weights from {old_weights} to {new_weights}")

    def get_weights(self) -> Dict[str, float]:
        """Get current feature weights."""
        return self.weights.copy()
