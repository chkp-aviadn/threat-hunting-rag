"""Pytest configuration and fixtures for test suite.

Configures separate test logging to avoid polluting application logs.
"""

import logging
import logging.handlers
from pathlib import Path
import os
import sys
import pytest
from typing import Any, Dict

# Instrumentation flags
INSTRUMENT_SEARCH = True
INSTRUMENT_API = True

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

TEST_LOG_DIR = Path("logs")
TEST_LOG_FILE = TEST_LOG_DIR / "test.log"


@pytest.fixture(scope="session", autouse=True)
def configure_test_logging():
    """Configure logging for test runs to separate file."""
    TEST_LOG_DIR.mkdir(parents=True, exist_ok=True)

    # Suppress telemetry
    os.environ.setdefault("CHROMA_TELEMETRY_DISABLED", "TRUE")
    os.environ.setdefault("ANONYMIZED_TELEMETRY", "FALSE")

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )

    # File handler for test logs
    file_handler = logging.handlers.RotatingFileHandler(
        TEST_LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)  # More verbose for tests

    # Console handler (pytest will capture this)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.WARNING)  # Less noisy in console during tests

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    # Clear any existing handlers
    for h in list(root.handlers):
        root.removeHandler(h)

    root.addHandler(file_handler)
    root.addHandler(console_handler)

    # Reduce noise from third-party loggers
    for noisy in [
        "chromadb.telemetry",
        "chromadb.telemetry.product.posthog",
        "posthog",
        "httpx",
        "uvicorn.error",
        "uvicorn.access",
    ]:
        logging.getLogger(noisy).setLevel(logging.ERROR)

    logging.info("=" * 80)
    logging.info("TEST SESSION STARTED")
    logging.info("=" * 80)

    yield

    logging.info("=" * 80)
    logging.info("TEST SESSION COMPLETED")
    logging.info("=" * 80)


@pytest.fixture(autouse=True)
def log_test_info(request):
    """Log test start/end for each test."""
    test_name = request.node.name
    logging.info(f"Starting test: {test_name}")
    yield
    logging.info(f"Finished test: {test_name}")


@pytest.fixture(autouse=True)
def instrument_unified_search(monkeypatch):
    """Monkeypatch UnifiedSearchService.search to log query and result summary.

    Adds per-call logging lines:
        SEARCH | query='<text>' method=<method> limit=<n>
        RESULTS | total=<count> levels=<set> avg_threat=<float>
    """
    if not INSTRUMENT_SEARCH:
        yield
        return
    try:
        from query_processing.services.unified_search import UnifiedSearchService
        from shared.enums import ThreatLevel
    except Exception:
        yield
        return

    original = UnifiedSearchService.search

    def _wrapped(self, query):  # type: ignore
        logging.info(
            "SEARCH | query='%s' method=%s limit=%s threshold=%s",
            query.text,
            getattr(query.method, "value", query.method),
            getattr(query, "limit", None),
            getattr(query, "threat_threshold", None),
        )
        res = original(self, query)
        if res and getattr(res, "results", None):
            levels = {getattr(r, "threat_level", None) for r in res.results}
            avg = 0.0
            if res.results:
                avg = sum(getattr(r, "threat_score", 0.0) for r in res.results) / len(res.results)
            logging.info(
                "RESULTS | total=%d levels=%s avg_threat=%.3f processing_ms=%s cache_hit=%s",
                res.total_found,
                sorted(l.value if hasattr(l, "value") else str(l) for l in levels if l),
                avg,
                getattr(res, "processing_time_ms", "?"),
                getattr(self, "_last_cache_hit", False),
            )
        return res

    monkeypatch.setattr(UnifiedSearchService, "search", _wrapped)
    yield


@pytest.fixture(autouse=True)
def instrument_fastapi_client(monkeypatch):
    """Instrument fastapi TestClient.post to log request/response summaries."""
    if not INSTRUMENT_API:
        yield
        return
    try:
        from fastapi.testclient import TestClient
    except Exception:
        yield
        return

    original_post = TestClient.post

    def _post(self, url: str, *args: Any, **kwargs: Any):  # type: ignore
        json_payload: Dict[str, Any] = kwargs.get("json", {}) or {}
        logging.info(
            "API_REQ | path=%s keys=%s size=%d",
            url,
            list(json_payload.keys()),
            len(str(json_payload)),
        )
        resp = original_post(self, url, *args, **kwargs)
        try:
            data = resp.json()
            if isinstance(data, dict):
                results = data.get("results") or data.get("turn", {}).get("results")
                total = data.get("total_results") or (
                    len(results) if isinstance(results, list) else "n/a"
                )
            else:
                total = "n/a"
        except Exception:
            total = "decode_error"
        logging.info(
            "API_RESP | path=%s status=%s total=%s latency_header=%s",
            url,
            resp.status_code,
            total,
            resp.headers.get("x-process-time"),
        )
        return resp

    monkeypatch.setattr(TestClient, "post", _post)
    yield
