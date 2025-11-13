"""Centralized logging configuration.

Usage:
    from shared.logging_config import init_logging
    init_logging()

Ensures all modules log to a single rotating file plus optional console.
"""

from __future__ import annotations
import logging
import logging.handlers
from pathlib import Path
import os

LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "app.log"

_initialized = False


def init_logging(level: int = logging.INFO) -> None:
    global _initialized
    if _initialized:
        return
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    # Telemetry suppression envs
    os.environ.setdefault("CHROMA_TELEMETRY_DISABLED", "TRUE")
    os.environ.setdefault("ANONYMIZED_TELEMETRY", "FALSE")

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )

    file_handler = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(level)

    root = logging.getLogger()
    root.setLevel(level)
    # Remove any pre-existing basicConfig handlers
    for h in list(root.handlers):
        root.removeHandler(h)
    root.addHandler(file_handler)
    root.addHandler(console_handler)

    # Reduce noisy third-party loggers if needed
    for noisy in [
        "chromadb.telemetry",
        "chromadb.telemetry.product.posthog",
        "posthog",
        "httpx",
        "uvicorn.error",
    ]:
        logging.getLogger(noisy).setLevel(logging.WARNING)

    _initialized = True


__all__ = ["init_logging", "LOG_FILE"]
