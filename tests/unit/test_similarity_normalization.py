from query_processing.models.search import SearchQuery, QueryResult
from shared.enums import SearchMethod
from threat_analysis.models.threat import ThreatFeatures
from orchestration.rag_pipeline import ThreatHuntingPipeline


class StubSearchService:
    def __init__(self, scores):
        self._scores = scores

    def search(self, query):
        from data_preparation.schemas.email import Email

        results = []
        for i, s in enumerate(self._scores):
            email = Email(
                id=f"e{i}",
                subject=f"Subj {i}",
                body="Body",
                sender="a@b.com",
                recipient="r@b.com",
                timestamp="2025-01-01T00:00:00Z",
            )
            qr = QueryResult(
                email=email,
                rank=i + 1,
                threat_score=0.2 + i * 0.01,
                threat_level="LOW",
                confidence=0.5,
                search_score=s,
                keyword_matches=[],
                semantic_similarity=None,
                features=ThreatFeatures(),
                explanation="",
                processing_time_ms=5,
            )
            results.append(qr)

        class R:
            pass

        r = R()
        r.results = results
        return r


def test_normalization_varied_scores():
    pipeline = ThreatHuntingPipeline(
        search_service=StubSearchService([0.1, 0.4, 0.7]),
        feature_extractor=None,
        threat_scorer=None,
        explanation_service=None,
    )
    q = SearchQuery(text="x", method=SearchMethod.HYBRID, limit=10)
    res = pipeline.process_query(q)
    sims = [r.semantic_similarity for r in res.results]
    assert sims == [0.0, 0.5, 1.0]


def test_normalization_identical_scores():
    pipeline = ThreatHuntingPipeline(
        search_service=StubSearchService([0.5, 0.5, 0.5]),
        feature_extractor=None,
        threat_scorer=None,
        explanation_service=None,
    )
    q = SearchQuery(text="x", method=SearchMethod.HYBRID, limit=10)
    res = pipeline.process_query(q)
    sims = [r.semantic_similarity for r in res.results]
    # When all raw equal, range becomes 1.0 via fallback -> all 0.0 after (raw-min)/range
    assert sims == [0.0, 0.0, 0.0]
