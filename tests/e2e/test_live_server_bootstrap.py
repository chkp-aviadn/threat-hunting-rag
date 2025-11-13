"""Live server bootstrap test.

Starts the application via `python app.py --api` on a test port, waits for readiness,
then validates root and health endpoints. Ensures bootstrap path works end-to-end.

This uses a subprocess instead of TestClient to exercise uvicorn + startup stack.
"""

from __future__ import annotations
import subprocess
import time
import os
import sys
import json
import socket
from pathlib import Path
from typing import Optional
import requests

ROOT = Path(__file__).resolve().parents[2]
PYTHON = sys.executable
TEST_HOST = "127.0.0.1"
TEST_PORT = 8123  # avoid 8000 collisions

API_KEY = os.getenv("TEST_API_KEY", "demo-key-12345")


def _wait_for_port(host: str, port: int, timeout: float = 20.0) -> bool:
    """Poll for TCP port availability."""
    start = time.time()
    while time.time() - start < timeout:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            try:
                if s.connect_ex((host, port)) == 0:
                    return True
            except OSError:
                pass
        time.sleep(0.5)
    return False


import pytest


@pytest.mark.filterwarnings("ignore::pydantic.PydanticDeprecatedSince20")
@pytest.mark.filterwarnings("ignore:.*json_encoders.*:pydantic.PydanticDeprecatedSince20")
@pytest.mark.filterwarnings("ignore:.*SwigPyPacked has no __module__ attribute:DeprecationWarning")
@pytest.mark.filterwarnings("ignore:.*SwigPyObject has no __module__ attribute:DeprecationWarning")
@pytest.mark.filterwarnings("ignore:.*swigvarlink has no __module__ attribute:DeprecationWarning")
def test_bootstrap_live_server_root_and_health():
    env = os.environ.copy()
    env["API_HOST"] = TEST_HOST
    env["API_PORT"] = str(TEST_PORT)
    # Disable reload explicitly to keep process stable
    env["API_RELOAD"] = "false"

    # Launch server
    # Use unbuffered output (-u) to ensure timely flush; avoid capturing stdout to prevent blocking.
    proc = subprocess.Popen(
        [PYTHON, "-u", "app.py", "--api", "--host", TEST_HOST, "--port", str(TEST_PORT)],
        cwd=str(ROOT),
        env=env,
        stdout=None,
        stderr=None,
        text=True,
    )
    try:
        assert _wait_for_port(TEST_HOST, TEST_PORT), "Server did not open port in time"
        # Extra grace for FastAPI startup
        time.sleep(2)

        root_resp = requests.get(f"http://{TEST_HOST}:{TEST_PORT}/", timeout=5)
        assert root_resp.status_code == 200, root_resp.text
        root_json = root_resp.json()
        assert root_json.get("status") == "operational"
        for ep in ["/api/v1/search", "/api/v1/search/refine", "/api/v1/chat", "/api/v1/health"]:
            assert any(
                ep in e for e in root_json.get("endpoints", [])
            ), f"Missing endpoint ref {ep}"

        health_resp = requests.get(
            f"http://{TEST_HOST}:{TEST_PORT}/api/v1/health",
            headers={"X-API-Key": API_KEY},
            timeout=8,
        )
        assert health_resp.status_code == 200, health_resp.text
        health_json = health_resp.json()
        assert health_json.get("status") in {"healthy", "degraded"}
        assert "components" in health_json and isinstance(health_json["components"], dict)
        assert "performance" in health_json

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=6)
        except subprocess.TimeoutExpired:
            proc.kill()

        # If failed, hint at manual log inspection instead of reading captured stdout
        if proc.returncode not in (0, None):
            print("Server failed; inspect logs or run manually: python app.py --api")
