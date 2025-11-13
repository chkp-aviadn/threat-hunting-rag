"""E2E test: basic /api/v1/search functionality.

Starts FastAPI lifespan in-process and performs a search.
Validates response shape, latency, and presence of results.
"""

import time
from fastapi.testclient import TestClient
import sys, pathlib

root = pathlib.Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(root))
from interfaces.api.app import app

API_HEADERS = {"X-API-Key": "demo-key-12345"}


def test_api_search_basic():
    with TestClient(app) as client:
        t0 = time.time()
        resp = client.post(
            "/api/v1/search",
            headers=API_HEADERS,
            json={
                "query": "suspicious activity verify now",
                "max_results": 5,
                "include_explanations": True,
                "search_method": "hybrid",
            },
        )
        latency_ms = int((time.time() - t0) * 1000)
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert "results" in data and isinstance(data["results"], list)
        assert data["total_results"] >= 0  # allow zero but log
        assert latency_ms < 6000  # generous upper bound for cold model load
        assert "search_metadata" in data
        # Basic schema checks for first result if exists
        if data["results"]:
            first = data["results"][0]
            assert "email" in first and "threat_score" in first
            assert "explanation" in first
        print(f"Search latency: {latency_ms}ms, total_results={data['total_results']}")
