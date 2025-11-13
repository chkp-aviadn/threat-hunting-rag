"""E2E test: /api/v1/search followed by /api/v1/search/refine.
Ensures refinement reduces or filters result set and returns metadata.
"""

import time
from fastapi.testclient import TestClient
import sys, pathlib

root = pathlib.Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(root))
from interfaces.api.app import app

API_HEADERS = {"X-API-Key": "demo-key-12345"}


def test_api_search_and_refine_flow():
    with TestClient(app) as client:
        base = client.post(
            "/api/v1/search",
            headers=API_HEADERS,
            json={
                "query": "urgent wire transfer invoice",
                "max_results": 6,
                "include_explanations": True,
                "search_method": "hybrid",
            },
        )
        assert base.status_code == 200, base.text
        body = base.json()
        req_id = body["request_id"]
        assert req_id
        threshold = 0.2
        refine = client.post(
            "/api/v1/search/refine",
            headers=API_HEADERS,
            json={
                "previous_request_id": req_id,
                "add_filters": {"feature_contains": "suspicious"},
                "adjust_threshold": threshold,
                "limit": 3,
                "explanation_focus": "attachments",
            },
        )
        assert refine.status_code == 200, refine.text
        rj = refine.json()
        assert rj["previous_request_id"] == req_id
        assert rj["total_results"] <= 3
        # Validate threshold enforcement
        for r in rj.get("results", []):
            assert (
                r.get("threat_score", 0) >= threshold
            ), f"Result below threshold: {r.get('threat_score')} < {threshold}"
        assert "applied_filters" in rj and rj["applied_filters"]
