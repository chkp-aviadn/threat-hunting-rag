"""
End-to-end RAG pipeline for threat hunting system.

Orchestrates the complete flow from query to results with explanations:
Query → Retrieval → Feature Extraction → Scoring → Explanation → Results

Implements Phase 6 integration: connects explanation generation with
existing threat analysis components for complete system functionality.
"""

import logging
import time
from typing import List, Optional
from dataclasses import dataclass

from data_preparation.schemas.email import Email
from query_processing.models.search import SearchQuery, SearchResults, QueryResult
from threat_analysis.models.threat import ThreatFeatures
from shared.constants import (
    EXPLANATION_DETAILED_THRESHOLD,
    EXPLANATION_COMPACT_THRESHOLD,
    EXPLANATION_COMPACT_MAX_INDICATORS,
    BLEND_WEIGHT_SCORER,
    BLEND_WEIGHT_ORIGINAL,
    CONFIDENCE_FEATURE_BONUS,
)
from threat_analysis.reasoning.integration import ExplanationFactory
import sys
import os

# Add src to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))

from shared.enums import ThreatLevel

logger = logging.getLogger(__name__)


@dataclass
class PipelineResult:
    """Complete result from the RAG pipeline."""

    email: Email
    features: ThreatFeatures
    threat_score: float
    threat_level: ThreatLevel
    confidence: float
    search_score: float
    explanation: str
    processing_time_ms: int


class ThreatHuntingPipeline:
    """
    End-to-end RAG pipeline for threat hunting.

    Coordinates retrieval, analysis, scoring, and explanation generation
    to provide comprehensive threat hunting results with human-readable explanations.
    """

    def __init__(
        self,
        search_service=None,
        feature_extractor=None,
        threat_scorer=None,
        explanation_service=None,
    ):
        """
        Initialize the pipeline with required services.

        Args:
            search_service: Service for retrieving relevant emails
            feature_extractor: Service for extracting threat features
            threat_scorer: Service for calculating threat scores
            explanation_service: Service for generating explanations
        """
        self.search_service = search_service
        self.feature_extractor = feature_extractor
        self.threat_scorer = threat_scorer

        # Use explanation factory if no service provided
        self.explanation_service = explanation_service or ExplanationFactory.get_explainer()

        logger.info("Initialized ThreatHuntingPipeline with explanation generation")

    def process_query(self, query: SearchQuery) -> SearchResults:
        """
        Process a complete threat hunting query.

        Implements the full pipeline flow:
        1. Search for relevant emails
        2. Extract threat features from each result
        3. Calculate threat scores and confidence
        4. Generate human-readable explanations
        5. Return ranked results with explanations

        Args:
            query: The threat hunting query

        Returns:
            Complete search results with threat analysis and explanations
        """
        start_time = time.time()

        try:
            logger.info(f"Processing query: '{query.text}' using {query.method.value} search")

            # Step 1: Retrieve relevant emails using UnifiedSearchService
            # This implements: CSV → VectorIndexBuilder → ChromaDB → Semantic Search
            if self.search_service:
                search_results = self.search_service.search(query)

                # UnifiedSearchService returns results with threat analysis already done
                # Convert to our QueryResult format for compatibility
                query_results = []
                # Compute min-max similarity range for normalization
                raw_scores = [
                    r.search_score
                    for r in search_results.results
                    if getattr(r, "search_score", None) is not None
                ]
                sim_min = min(raw_scores) if raw_scores else 0.0
                sim_max = max(raw_scores) if raw_scores else 1.0
                score_range = (sim_max - sim_min) or 1.0

                for result in search_results.results:
                    # Enhance with additional pipeline processing if needed
                    enhanced_result = self._enhance_search_result(result, query)
                    # Attach normalized similarity score
                    try:
                        raw = enhanced_result.search_score or 0.0
                        enhanced_result.semantic_similarity = round(
                            (raw - sim_min) / score_range, 3
                        )
                    except Exception:
                        enhanced_result.semantic_similarity = None
                    query_results.append(enhanced_result)

                # Apply threat threshold filtering AFTER enhancement/blending so final scores respected
                if query.threat_threshold is not None:
                    original_count = len(query_results)
                    # Preserve original enhanced results for potential fallback
                    original_enhanced_results = list(query_results)
                    query_results = [
                        r for r in query_results if r.threat_score >= query.threat_threshold
                    ]
                    if len(query_results) != original_count:
                        logger.debug(
                            f"Threshold filter applied: {original_count}->{len(query_results)} (threshold={query.threat_threshold})"
                        )
                    # Fallback: if filtering removed all results, return original set unfiltered
                    if original_count > 0 and len(query_results) == 0:
                        logger.debug(
                            "Threshold filter produced zero results; falling back to unfiltered set for user visibility"
                        )
                        query_results = original_enhanced_results
                        # (Optional) we could tag results/explanations but keeping minimal change for compatibility
                    # Re-rank results after filtering
                    for i, r in enumerate(query_results):
                        r.rank = i + 1

            else:
                # Fallback for testing - empty results
                query_results = []
                logger.warning("No search service configured, returning empty results")

            end_time = time.time()
            processing_time_ms = int((end_time - start_time) * 1000)

            results = SearchResults(
                query=query,
                results=query_results,
                total_found=len(query_results),
                processing_time_ms=processing_time_ms,
            )

            logger.info(
                f"Processed query in {processing_time_ms}ms, found {len(query_results)} results"
            )
            return results

        except Exception as e:
            logger.error(f"Pipeline error: {e}")
            # Return empty results on error
            end_time = time.time()
            processing_time_ms = int((end_time - start_time) * 1000)

            return SearchResults(
                query=query, results=[], total_found=0, processing_time_ms=processing_time_ms
            )

    def _process_single_email(self, email: Email, query: SearchQuery, rank: int) -> PipelineResult:
        """
        Process a single email through the complete pipeline.

        Args:
            email: Email to process
            query: Original query for context
            rank: Result ranking

        Returns:
            Complete pipeline result with explanation
        """
        start_time = time.time()

        # Step 2: Extract threat features
        if self.feature_extractor:
            features = self.feature_extractor.extract_features(email)
        else:
            # Fallback for testing
            features = ThreatFeatures()

        # Step 3: Calculate threat scores
        if self.threat_scorer:
            threat_result = self.threat_scorer.score_email(email)
            threat_score = threat_result.overall_score
            threat_level = threat_result.threat_level
            confidence = threat_result.confidence
        else:
            # Fallback for testing
            threat_score = 0.1
            threat_level = ThreatLevel.LOW
            confidence = 0.5

        # Step 4: Generate explanation using Phase 6 explainer
        explanation = self.explanation_service.explain_threat(email, features)

        # Calculate search relevance (simplified for now)
        search_score = 0.5  # Would be calculated by search service

        end_time = time.time()
        processing_time_ms = int((end_time - start_time) * 1000)

        return PipelineResult(
            email=email,
            features=features,
            threat_score=threat_score,
            threat_level=threat_level,
            confidence=confidence,
            search_score=search_score,
            explanation=explanation,
            processing_time_ms=processing_time_ms,
        )

    def _enhance_search_result(self, result: QueryResult, query: SearchQuery) -> QueryResult:
        """Enhance search results with full threat feature extraction + scoring + rich explanation.

        Production readiness improvements:
        - Integrates FeatureExtractor + ThreatScorer for real feature scores
        - Recalculates threat_score & confidence using weighted model instead of heuristic-only
        - Generates layered explanation (relevance + triggered indicators + remediation hint)
        - Maintains original search relevance portion from UnifiedSearchService for transparency
        """
        try:
            # 1. Extract real features (falls back gracefully)
            extracted_features = None
            if self.feature_extractor:
                try:
                    # Support both extract_features (legacy) and extract_all_features (new) APIs
                    if hasattr(self.feature_extractor, "extract_all_features"):
                        extracted_features = self.feature_extractor.extract_all_features(
                            result.email
                        )
                    else:
                        extracted_features = self.feature_extractor.extract_features(result.email)
                except Exception as fe:
                    logger.debug(f"Feature extraction failed for {result.email.id}: {fe}")
            extracted_features = extracted_features or result.features or ThreatFeatures()
            result.features = extracted_features

            # 2. Threat scoring (weighted) replacing heuristic threat_score if scorer present
            if self.threat_scorer:
                try:
                    score_obj = self.threat_scorer.score_email(result.email)
                    # Blend existing similarity-based threat_score with weighted score for stability
                    blended_score = min(
                        1.0,
                        (score_obj.overall_score * BLEND_WEIGHT_SCORER)
                        + (result.threat_score * BLEND_WEIGHT_ORIGINAL),
                    )
                    result.threat_score = blended_score
                    result.threat_level = score_obj.threat_level
                    # Confidence combines similarity + number of detected high-confidence features
                    detected_features = sum(
                        1
                        for v in [
                            extracted_features.urgent_language,
                            extracted_features.suspicious_attachment,
                            extracted_features.executive_impersonation,
                            extracted_features.new_sender,
                        ]
                        if v and v >= 0.3
                    )
                    similarity_component = result.search_score or 0.0
                    feature_component = min(1.0, detected_features * CONFIDENCE_FEATURE_BONUS)
                    result.confidence = round(
                        min(
                            1.0,
                            (similarity_component * 0.6)
                            + (feature_component * 0.6)
                            + (score_obj.confidence * 0.4),
                        ),
                        3,
                    )
                except Exception as se:
                    logger.debug(f"Threat scoring failed for {result.email.id}: {se}")

            # 3. Generate enhanced explanation via explainer (detailed risk indicators)
            detailed_part = ""
            if self.explanation_service:
                try:
                    detailed_part = self.explanation_service.explain_threat(
                        result.email, extracted_features
                    )
                except Exception as ee:
                    logger.debug(f"Explainer failed for {result.email.id}: {ee}")
                    detailed_part = "No detailed analysis available."

            # Structured explanation builder (multi-line readable format + optional JSON)
            try:
                result.explanation, result.explanation_structured = self._build_explanation(
                    result=result,
                    features=extracted_features,
                    detailed_part=detailed_part,
                    mode=getattr(query, "explanation_mode", "text"),
                    detail_level=getattr(query, "detail_level", "detailed"),
                )
            except Exception as be:
                logger.debug(f"Explanation build failed for {result.email.id}: {be}")
                # Fallback to prior simple format
                result.explanation = (
                    f"ThreatScore={result.threat_score:.3f}; Level={getattr(result.threat_level,'value',result.threat_level)}"
                    f"\n\nDetailed Analysis: {detailed_part}".strip()
                )
            return result
        except Exception as e:
            logger.error(
                f"Error enhancing search result for email {getattr(result.email,'id','unknown')}: {e}"
            )
            return result

    def _build_explanation(
        self,
        *,
        result: QueryResult,
        features: ThreatFeatures,
        detailed_part: str,
        mode: str = "text",
        detail_level: str = "detailed",
    ):
        """Create human-readable (and optionally structured JSON) explanation.

        Sections:
        - Overview
        - Key Indicators (score >= threshold)
        - Risk Summary
        - Recommended Action

        Returns tuple: (text_explanation, structured_dict or None)
        """
        # 1. Collect overview metrics
        overview = {
            "threat_level": getattr(result.threat_level, "value", str(result.threat_level)),
            "threat_score": round(result.threat_score, 3),
            "similarity_raw": round(result.search_score or 0.0, 3),
            "similarity_norm": getattr(result, "semantic_similarity", None),
            "confidence": round(result.confidence, 3),
            "rank": result.rank,
        }

        # 2. Build indicators list (with interpretations)
        interpretations = {
            "urgent_language": "Urgent wording requesting immediate action",
            "suspicious_language": "Suspicious / coercive phrasing",
            "executive_impersonation": "Appears to mimic an executive or authority",
            "new_sender": "Sender not previously recognized",
            "domain_suspicious": "Domain appears unusual or mismatched",
            "suspicious_attachment": "Attachment with potential risk",
            "executable_attachment": "Executable / script attachment detected",
            "financial_request": "Payment / transfer instructions present",
            "credential_harvest": "Login / credential capture attempt",
            "link_suspicious": "Link appears obfuscated or mismatched",
            "outside_hours": "Sent outside typical business hours",
        }
        # Choose threshold (compact mode raises threshold further) and cap indicators
        base_threshold = (
            EXPLANATION_DETAILED_THRESHOLD
            if detail_level == "detailed"
            else EXPLANATION_COMPACT_THRESHOLD
        )
        indicators = []
        try:
            for name, val in features.get_top_features(threshold=base_threshold).items():
                if name in interpretations:
                    indicators.append(
                        {
                            "name": name,
                            "score": round(val, 2),
                            "interpretation": interpretations[name],
                        }
                    )
            if detail_level == "compact":
                indicators = indicators[:EXPLANATION_COMPACT_MAX_INDICATORS]
        except Exception:
            pass

        # 3. Derive risk summary heuristic
        summary_parts = []
        feat_vals = {k: getattr(features, k, 0.0) for k in interpretations.keys()}
        if (
            feat_vals.get("financial_request", 0) >= 0.4
            and feat_vals.get("urgent_language", 0) >= 0.4
        ):
            summary_parts.append(
                "Financial request coupled with urgency signals potential payment fraud"
            )
        if feat_vals.get("credential_harvest", 0) >= 0.4:
            summary_parts.append(
                "Credential harvesting indicators present – risk of account compromise"
            )
        if feat_vals.get("executive_impersonation", 0) >= 0.4:
            summary_parts.append(
                "Possible executive impersonation (business email compromise pattern)"
            )
        if not summary_parts:
            summary_parts.append(
                "Multiple moderate indicators; monitor and verify via trusted channel"
            )
        risk_summary = summary_parts[0] if detail_level == "compact" else "; ".join(summary_parts)

        # 4. Recommended action (severity-driven)
        lvl = overview["threat_level"]
        if lvl in ("HIGH", "CRITICAL"):
            recommended = "Escalate: Validate sender and instructions out-of-band before acting; scan attachments."
        elif lvl == "MEDIUM":
            recommended = (
                "Verify sender authenticity and scrutinize any financial or credential requests."
            )
        else:
            recommended = "Low immediate risk; continue monitoring for patterns."

        # 5. Structured dict
        structured = {
            "overview": overview,
            "indicators": indicators,
            "risk_summary": risk_summary,
            "recommended_action": recommended,
            "analysis_detail": detailed_part[:2000],  # truncate excessively long analysis
        }

        # 6. Text formatting
        sim_display = (
            f"Similarity(norm={overview['similarity_norm']}, raw={overview['similarity_raw']})"
            if overview.get("similarity_norm") is not None
            else f"Similarity={overview['similarity_raw']}"
        )
        lines = [
            "Overview:",
            f"- Threat Level: {overview['threat_level']} ({overview['threat_score']})",
            f"- {sim_display} | Confidence: {overview['confidence']} | Rank: {overview['rank']}",
        ]
        if indicators:
            lines.append("\nKey Indicators:")
            for ind in indicators:
                lines.append(f"- {ind['name']} {ind['score']} – {ind['interpretation']}")
        lines.append("\nRisk Summary:")
        lines.append(f"- {risk_summary}")
        lines.append("\nRecommended Action:")
        lines.append(f"- {recommended}")
        if detail_level == "detailed" and detailed_part:
            lines.append("\nAnalysis Detail:")
            lines.append(f"{detailed_part.strip()}")

        text_explanation = "\n".join(lines).strip()

        if mode == "json":
            return text_explanation, structured
        return text_explanation, None

    def _build_query_results(
        self, pipeline_results: List[PipelineResult], query: SearchQuery
    ) -> List[QueryResult]:
        """
        Convert pipeline results to QueryResult objects.

        Args:
            pipeline_results: List of pipeline results
            query: Original search query

        Returns:
            List of QueryResult objects with explanations
        """
        query_results = []

        for i, result in enumerate(pipeline_results):
            # Apply threat threshold filtering if specified
            if query.threat_threshold and result.threat_score < query.threat_threshold:
                continue

            query_result = QueryResult(
                email=result.email,
                rank=i + 1,
                threat_score=result.threat_score,
                threat_level=result.threat_level,
                confidence=result.confidence,
                search_score=result.search_score,
                keyword_matches=[],  # Would be populated by search service
                semantic_similarity=None,  # Would be populated by search service
                features=result.features,
                explanation=result.explanation,  # Phase 6: Enhanced explanations
                processing_time_ms=result.processing_time_ms,
            )
            query_results.append(query_result)

        # Sort by threat score (highest first)
        query_results.sort(key=lambda x: x.threat_score, reverse=True)

        # Update rankings after sorting
        for i, result in enumerate(query_results):
            result.rank = i + 1

        return query_results[: query.limit]


class PipelineBuilder:
    """
    Builder pattern for constructing threat hunting pipeline.

    Automatically configures the complete data flow:
    CSV File → VectorIndexBuilder → ChromaDB → Semantic Search → RAG Pipeline
    """

    def __init__(self):
        self.search_service = None
        self.feature_extractor = None
        self.threat_scorer = None
        self.explanation_service = None

    def with_search_service(self, service):
        """Add search service to pipeline."""
        self.search_service = service
        return self

    def with_feature_extractor(self, extractor):
        """Add feature extractor to pipeline."""
        self.feature_extractor = extractor
        return self

    def with_threat_scorer(self, scorer):
        """Add threat scorer to pipeline."""
        self.threat_scorer = scorer
        return self

    def with_explanation_service(self, explainer):
        """Add explanation service to pipeline."""
        self.explanation_service = explainer
        return self

    def build(self) -> ThreatHuntingPipeline:
        """Build the configured pipeline with automatic search service setup."""

        # If no search service is configured, use our UnifiedSearchService
        # This implements the complete flow: CSV → ChromaDB → Semantic Search
        if self.search_service is None:
            try:
                from query_processing.services.unified_search import UnifiedSearchService

                self.search_service = UnifiedSearchService()
                logger.info(
                    "✅ Configured UnifiedSearchService for complete CSV→ChromaDB→Search flow"
                )
            except Exception as e:
                logger.warning(f"Could not configure UnifiedSearchService: {e}")

        # Auto-wire feature extractor & threat scorer if not provided for production readiness
        if self.feature_extractor is None:
            try:
                from threat_analysis.detection.features import FeatureExtractor

                self.feature_extractor = FeatureExtractor()
                logger.info("✅ Auto-wired FeatureExtractor for real threat feature analysis")
            except Exception as e:
                logger.warning(f"Failed to initialize FeatureExtractor: {e}")
        if self.threat_scorer is None:
            try:
                from threat_analysis.detection.scorer import ThreatScorer

                self.threat_scorer = ThreatScorer()
                logger.info("✅ Auto-wired ThreatScorer for weighted risk scoring")
            except Exception as e:
                logger.warning(f"Failed to initialize ThreatScorer: {e}")

        return ThreatHuntingPipeline(
            search_service=self.search_service,
            feature_extractor=self.feature_extractor,
            threat_scorer=self.threat_scorer,
            explanation_service=self.explanation_service,
        )
