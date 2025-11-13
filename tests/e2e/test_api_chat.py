"""E2E test: /api/v1/chat session behavior.
Validates session continuity and refinement path.
"""

from fastapi.testclient import TestClient
import sys, pathlib

root = pathlib.Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(root))
from interfaces.api.app import app

API_HEADERS = {"X-API-Key": "demo-key-12345"}


def test_chat_session_and_refinement():
    with TestClient(app) as client:
        r1 = client.post(
            "/api/v1/chat",
            headers=API_HEADERS,
            json={"message": "urgent wire transfer invoice", "limit": 5},
        )
        assert r1.status_code == 200, r1.text
        j1 = r1.json()
        session_id = j1["session_id"]
        assert j1["conversation_length"] == 1
        assert j1["turn"]["suggestions"]
        r2 = client.post(
            "/api/v1/chat",
            headers=API_HEADERS,
            json={
                "message": "refine suspicious attachments",
                "session_id": session_id,
                "refine": True,
                "focus_feature": "suspicious",
                "min_threat_score": 0.3,
            },
        )
        assert r2.status_code == 200, r2.text
        j2 = r2.json()
        assert j2["conversation_length"] == 2
        assert "refined" in j2
        assert j2["turn"]["suggestions"]
