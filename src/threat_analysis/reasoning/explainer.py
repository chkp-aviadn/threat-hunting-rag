"""
Explanation generation module for threat analysis results.

Implements Phase 6: Rule-based explanation generation with optional LLM enhancement.
Provides human-readable explanations for threat detections and search relevance.
"""

import logging
from typing import List, Dict, Optional
from dataclasses import dataclass

from data_preparation.schemas.email import Email
from threat_analysis.models.threat import ThreatFeatures
from query_processing.models.search import SearchQuery
from .interfaces import ExplanationService

logger = logging.getLogger(__name__)


@dataclass
class FeatureExplanation:
    """Individual feature explanation with confidence."""

    feature_name: str
    score: float
    threshold: float
    explanation: str
    triggered: bool


class RuleBasedExplainer(ExplanationService):
    """
    Rule-based explanation generator for threat analysis.

    Maps detected threat features to human-readable explanations
    following the requirements from Task 6.1.
    """

    # Feature thresholds for triggering explanations
    FEATURE_THRESHOLDS = {
        "urgent_language": 0.3,
        "suspicious_language": 0.3,
        "executive_impersonation": 0.4,
        "new_sender": 0.2,
        "domain_suspicious": 0.3,
        "suspicious_attachment": 0.3,
        "executable_attachment": 0.5,
        "financial_request": 0.3,
        "credential_harvest": 0.4,
        "link_suspicious": 0.3,
        "outside_hours": 0.2,
    }

    # Human-readable explanations for each feature
    FEATURE_EXPLANATIONS = {
        "urgent_language": "Contains urgent language requiring immediate action",
        "suspicious_language": "Uses suspicious or deceptive phrasing patterns",
        "executive_impersonation": "Potential executive impersonation detected",
        "new_sender": "Email from unknown or rarely-contacted sender",
        "domain_suspicious": "Sender domain appears suspicious or spoofed",
        "suspicious_attachment": "Contains suspicious attachment types",
        "executable_attachment": "Contains potentially dangerous executable files",
        "financial_request": "Requests financial information or transactions",
        "credential_harvest": "Attempts to harvest login credentials or personal data",
        "link_suspicious": "Contains suspicious or potentially malicious links",
        "outside_hours": "Sent outside typical business hours",
    }

    def __init__(self, min_explanation_threshold: float = 0.2):
        """
        Initialize the rule-based explainer.

        Args:
            min_explanation_threshold: Minimum feature score to include in explanations
        """
        self.min_threshold = min_explanation_threshold
        logger.info(f"Initialized RuleBasedExplainer with threshold {min_explanation_threshold}")

    def explain_threat(self, email: Email, features: ThreatFeatures) -> str:
        """
        Generate human-readable explanation for threat detection.

        Maps detected features to clear explanations following Task 6.1 requirements:
        - "Contains urgent language: 'immediate action required'"
        - "Suspicious attachment detected: invoice.exe"
        - "Potential executive impersonation: claims to be from CEO"

        Args:
            email: The email being analyzed
            features: Extracted threat features with scores

        Returns:
            Human-readable explanation string
        """
        try:
            explanations = self._generate_feature_explanations(features)

            if not explanations:
                return "No significant threat indicators detected."

            # Build comprehensive explanation
            explanation_parts = []

            # Add high-confidence threats first
            high_confidence = [exp for exp in explanations if exp.score >= 0.6]
            medium_confidence = [exp for exp in explanations if 0.3 <= exp.score < 0.6]
            low_confidence = [exp for exp in explanations if exp.score < 0.3]

            if high_confidence:
                explanation_parts.append("⚠️ HIGH RISK INDICATORS:")
                for exp in high_confidence:
                    explanation_parts.append(f"  • {exp.explanation} (confidence: {exp.score:.1%})")

            if medium_confidence:
                if high_confidence:
                    explanation_parts.append("")
                explanation_parts.append("⚡ MODERATE RISK INDICATORS:")
                for exp in medium_confidence:
                    explanation_parts.append(f"  • {exp.explanation} (confidence: {exp.score:.1%})")

            if low_confidence and not (high_confidence or medium_confidence):
                explanation_parts.append("LOW RISK INDICATORS:")
                for exp in low_confidence:
                    explanation_parts.append(f"  • {exp.explanation} (confidence: {exp.score:.1%})")

            # Add contextual information
            if email.sender:
                explanation_parts.append(f"\nEmail from: {email.sender}")
            if email.subject:
                explanation_parts.append(f"Subject: {email.subject[:100]}...")

            return "\n".join(explanation_parts)

        except Exception as e:
            logger.error(f"Error generating threat explanation: {e}")
            return f"Error generating explanation: {str(e)}"

    def explain_search_relevance(self, email: Email, query: SearchQuery, score: float) -> str:
        """
        Explain why email matched the search query.

        Args:
            email: The matching email
            query: The search query
            score: Relevance score

        Returns:
            Explanation of search match
        """
        try:
            explanation_parts = []

            # Search relevance explanation
            relevance_level = self._get_relevance_level(score)
            explanation_parts.append(f"Search relevance: {relevance_level} (score: {score:.2f})")

            # Query analysis
            if query.text:
                explanation_parts.append(f"Query: '{query.text}'")

                # Simple keyword matching analysis
                query_words = set(query.text.lower().split())
                email_content = f"{email.subject or ''} {email.body or ''}".lower()
                matched_words = [word for word in query_words if word in email_content]

                if matched_words:
                    explanation_parts.append(f"Matched keywords: {', '.join(matched_words)}")

            # Email context
            if email.sender:
                explanation_parts.append(f"From: {email.sender}")
            if email.subject:
                explanation_parts.append(f"Subject: {email.subject}")

            return "\n".join(explanation_parts)

        except Exception as e:
            logger.error(f"Error generating search relevance explanation: {e}")
            return f"Error explaining search relevance: {str(e)}"

    def _generate_feature_explanations(self, features: ThreatFeatures) -> List[FeatureExplanation]:
        """Generate explanations for all triggered features."""
        explanations = []
        # For Pydantic v2 we standardize on model_dump(); legacy v1 fallback removed
        feature_dict = features.model_dump()

        for feature_name, score in feature_dict.items():
            # Skip metadata fields
            if feature_name in ["extraction_timestamp", "feature_version"]:
                continue

            threshold = self.FEATURE_THRESHOLDS.get(feature_name, self.min_threshold)

            if score >= threshold and feature_name in self.FEATURE_EXPLANATIONS:
                explanation = FeatureExplanation(
                    feature_name=feature_name,
                    score=score,
                    threshold=threshold,
                    explanation=self.FEATURE_EXPLANATIONS[feature_name],
                    triggered=True,
                )
                explanations.append(explanation)

        # Sort by score (highest first)
        explanations.sort(key=lambda x: x.score, reverse=True)
        return explanations

    def _get_relevance_level(self, score: float) -> str:
        """Convert numeric score to human-readable relevance level."""
        if score >= 0.8:
            return "Very High"
        elif score >= 0.6:
            return "High"
        elif score >= 0.4:
            return "Medium"
        elif score >= 0.2:
            return "Low"
        else:
            return "Very Low"


class EnhancedExplainer(RuleBasedExplainer):
    """
    Enhanced explainer with optional LLM integration (Task 6.2).

    Falls back to rule-based explanations if LLM is unavailable.
    """

    def __init__(self, llm_client=None, min_explanation_threshold: float = 0.2):
        """
        Initialize enhanced explainer with optional LLM.

        Args:
            llm_client: Optional LLM client (e.g., OpenAI)
            min_explanation_threshold: Minimum feature score threshold
        """
        super().__init__(min_explanation_threshold)
        self.llm_client = llm_client
        self.use_llm = llm_client is not None
        logger.info(f"Enhanced explainer initialized with LLM: {self.use_llm}")

    def explain_threat(self, email: Email, features: ThreatFeatures) -> str:
        """
        Generate explanation using LLM if available, fallback to rule-based.

        Args:
            email: The email being analyzed
            features: Extracted threat features

        Returns:
            Enhanced human-readable explanation
        """
        if not self.use_llm:
            return super().explain_threat(email, features)

        try:
            # Generate LLM-enhanced explanation
            return self._generate_llm_explanation(email, features)
        except Exception as e:
            logger.warning(f"LLM explanation failed, falling back to rule-based: {e}")
            return super().explain_threat(email, features)

    def _generate_llm_explanation(self, email: Email, features: ThreatFeatures) -> str:
        """
        Generate LLM-based explanation (placeholder for Task 6.2).

        This would integrate with OpenAI or other LLM APIs when implemented.
        """
        # For now, return enhanced rule-based explanation
        base_explanation = super().explain_threat(email, features)

        # Add LLM enhancement context (when implemented)
        enhanced_explanation = f"""
THREAT ANALYSIS SUMMARY:
{base_explanation}

(Enhanced explanations via LLM would be implemented here in Task 6.2)
"""
        return enhanced_explanation.strip()
