import pytest
from threat_analysis.models.threat import ThreatFeatures
from query_processing.models.search import QueryResult, SearchQuery
from shared.enums import SearchMethod
from orchestration.rag_pipeline import ThreatHuntingPipeline


class DummySearchService:
    def search(self, query):
        # Minimal stub returning one result-like object with necessary attrs
        features = ThreatFeatures(
            urgent_language=0.7,
            financial_request=0.8,
            credential_harvest=0.0,
            executive_impersonation=0.5,
            suspicious_attachment=0.65,
            new_sender=0.6,
        )
        from data_preparation.schemas.email import Email

        email = Email(
            id="e1",
            subject="Urgent payment needed",
            body="Please pay now",
            sender="boss@example.com",
            recipient="user@example.com",
            timestamp="2025-01-01T00:00:00Z",
        )
        qr = QueryResult(
            email=email,
            rank=1,
            threat_score=0.75,
            threat_level="HIGH",  # will be normalized by validator
            confidence=0.9,
            search_score=0.8,
            keyword_matches=["urgent"],
            semantic_similarity=0.82,
            features=features,
            explanation="placeholder",
            processing_time_ms=10,
        )

        class R:  # mimic SearchResults-like object
            results = [qr]

        return R()


def build_pipeline():
    # Pipeline will enhance results using feature_extractor/threat_scorer if present; we omit to keep deterministic
    return ThreatHuntingPipeline(
        search_service=DummySearchService(),
        feature_extractor=None,
        threat_scorer=None,
        explanation_service=None,
    )


def test_compact_vs_detailed_indicator_count():
    pipeline = build_pipeline()
    base_query = SearchQuery(
        text="urgent payment", method=SearchMethod.HYBRID, limit=5, explanation_mode="text"
    )
    # Detailed
    # Use Pydantic model_copy() to avoid deprecated BaseModel.copy()
    detailed_query = base_query.model_copy()
    detailed_query.detail_level = "detailed"
    detailed_results = pipeline.process_query(detailed_query)
    detailed_indicators = detailed_results.results[0].explanation.count("Key Indicators:")
    assert detailed_indicators == 1
    # Compact
    compact_query = base_query.model_copy()
    compact_query.detail_level = "compact"
    compact_results = pipeline.process_query(compact_query)
    # Ensure explanation present and fewer indicator lines (cap of 3 vs potentially more)
    detailed_lines = [
        l
        for l in detailed_results.results[0].explanation.splitlines()
        if l.startswith("- ") and "Indicators" not in l
    ]
    compact_lines = [
        l
        for l in compact_results.results[0].explanation.splitlines()
        if l.startswith("- ") and "Indicators" not in l
    ]
    # Rough heuristic: compact should not exceed 3 indicator interpretations lines
    compact_indicator_lines = [l for l in compact_lines if "–" in l and "Threat Level" not in l]
    assert len(compact_indicator_lines) <= 3


def test_json_mode_structured_present():
    pipeline = build_pipeline()
    query = SearchQuery(
        text="urgent payment",
        method=SearchMethod.HYBRID,
        limit=5,
        explanation_mode="json",
        detail_level="compact",
    )
    results = pipeline.process_query(query)
    structured = results.results[0].explanation_structured
    assert structured is not None
    assert (
        "overview" in structured
        and "indicators" in structured
        and "recommended_action" in structured
    )
