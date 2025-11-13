"""E2E tests for minimal mode auxiliary endpoints: /api/v1/health and root /."""

from fastapi.testclient import TestClient
import sys, pathlib

root = pathlib.Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(root))
from interfaces.api.app import app  # noqa: E402

API_HEADERS = {"X-API-Key": "demo-key-12345"}


def test_health_endpoint():
    with TestClient(app) as client:
        resp = client.get("/api/v1/health", headers=API_HEADERS)
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert "status" in data and "components" in data
        assert data["status"] in {"healthy", "degraded", "unhealthy", "unknown"}
        # Basic expected component keys (may vary but at least one)
        assert isinstance(data.get("components"), dict)
        assert data.get("version")
        assert data.get("uptime_seconds") >= 0


def test_root_metadata():
    with TestClient(app) as client:
        resp = client.get("/")
        assert resp.status_code == 200, resp.text
        data = resp.json()
        # Minimal shape: name, version, endpoints list
        assert "name" in data and "version" in data
        assert "endpoints" in data and isinstance(data["endpoints"], list)
        # Confirm advertised critical endpoints present
        for ep in ["/api/v1/search", "/api/v1/search/refine", "/api/v1/chat", "/api/v1/health"]:
            assert any(ep in e for e in data["endpoints"]), f"Missing endpoint reference: {ep}"
