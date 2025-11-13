"""Unit tests for structured explanation modes.

Validates:
- JSON explanation mode returns structured object with required keys
- Compact vs detailed modes differ in indicator count and text verbosity
"""

import sys, pathlib

root = pathlib.Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(root))

from orchestration.rag_pipeline import PipelineBuilder
from query_processing.models.search import SearchQuery
from shared.enums import SearchMethod


def _pipeline():
    builder = PipelineBuilder()
    return builder.build()


def test_json_explanation_contains_keys():
    pipeline = _pipeline()
    q = SearchQuery(
        text="urgent wire transfer payment",
        method=SearchMethod.HYBRID,
        limit=3,
        explanation_mode="json",
        detail_level="detailed",
    )
    results = pipeline.process_query(q)
    assert results.results, "Expected at least one result for test query"
    first = results.results[0]
    assert first.explanation_structured is not None, "Structured explanation missing"
    keys = set(first.explanation_structured.keys())
    expected = {"overview", "indicators", "risk_summary", "recommended_action", "analysis_detail"}
    assert expected.issubset(keys), f"Missing keys in structured explanation: {expected - keys}"
    overview = first.explanation_structured["overview"]
    assert (
        "threat_score" in overview and "threat_level" in overview
    ), "Overview missing core metrics"


def test_compact_mode_reduces_indicators():
    pipeline = _pipeline()
    detailed_q = SearchQuery(
        text="urgent wire transfer payment",
        method=SearchMethod.HYBRID,
        limit=3,
        explanation_mode="json",
        detail_level="detailed",
    )
    compact_q = SearchQuery(
        text="urgent wire transfer payment",
        method=SearchMethod.HYBRID,
        limit=3,
        explanation_mode="json",
        detail_level="compact",
    )
    detailed_res = pipeline.process_query(detailed_q)
    compact_res = pipeline.process_query(compact_q)
    assert detailed_res.results and compact_res.results, "Need results for both modes"
    d_inds = len(detailed_res.results[0].explanation_structured.get("indicators", []))
    c_inds = len(compact_res.results[0].explanation_structured.get("indicators", []))
    # Compact should not produce more indicators than detailed, and usually fewer
    assert c_inds <= d_inds, f"Compact mode has more indicators ({c_inds}) than detailed ({d_inds})"
    # Text explanation should be shorter in compact mode
    d_lines = len(detailed_res.results[0].explanation.split("\n"))
    c_lines = len(compact_res.results[0].explanation.split("\n"))
    assert c_lines <= d_lines, "Compact explanation has more lines than detailed"
