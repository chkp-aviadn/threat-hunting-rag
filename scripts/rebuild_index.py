#!/usr/bin/env python
"""Rebuild semantic vector index for the threat-hunting-rag project.

Steps:
1. Ensure dataset exists at data/emails.csv; if missing, generate synthetic dataset (150 emails, 70% legitimate / 30% phishing).
2. Load dataset rows into list of dicts.
3. Build Chroma persistent index via VectorIndexBuilder.

Usage:
  python scripts/rebuild_index.py

Optional environment vars:
  EMAIL_DATASET_PATH   Override dataset path (default data/emails.csv)
  COLLECTION_NAME      Override Chroma collection name (default email_embeddings)

Safe to run multiple times; existing collection is cleared before rebuild.
"""
from __future__ import annotations
import os
import sys
import csv
import logging
from pathlib import Path
from typing import List, Dict, Any

# Basic logging
logging.basicConfig(level=logging.INFO, format="[rebuild-index] %(message)s")
logger = logging.getLogger("rebuild-index")

# Allow execution from repo root
ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.append(str(SRC))

DATASET_PATH = Path(os.getenv("EMAIL_DATASET_PATH", "data/emails.csv"))
COLLECTION_NAME = os.getenv("COLLECTION_NAME", "threat_hunting_emails")

# Import generators / builder
try:
    from data_preparation.generators.generate_dataset import EmailGenerator
    from data_preparation.embeddings.index_builder import VectorIndexBuilder
except ImportError as e:  # fallback if run via other PYTHONPATH semantics
    try:
        from src.data_preparation.generators.generate_dataset import EmailGenerator  # type: ignore
        from src.data_preparation.embeddings.index_builder import VectorIndexBuilder  # type: ignore
    except Exception:
        raise RuntimeError(f"Failed to import required modules: {e}")


def _generate_dataset_if_missing(path: Path) -> None:
    if path.exists():
        logger.info(f"Dataset present: {path}")
        return
    logger.info(f"Dataset missing, generating synthetic dataset -> {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    gen = EmailGenerator()

    total = 150
    legitimate = int(total * 0.7)
    phishing = total - legitimate

    emails: List[Dict[str, Any]] = []
    # Generate legitimate
    for _ in range(legitimate):
        emails.append(gen.generate_legitimate_email().__dict__)
    # Generate phishing
    for _ in range(phishing):
        emails.append(gen.generate_phishing_email().__dict__)

    # Normalize timestamps for CSV and ensure required columns
    import pandas as pd
    df = pd.DataFrame([
        {
            **e,
            "timestamp": e["timestamp"].isoformat() if hasattr(e["timestamp"], "isoformat") else e["timestamp"],
        }
        for e in emails
    ])
    df.to_csv(path, index=False)
    logger.info(f"Synthetic dataset written: {path} (rows={len(df)})")


def _load_dataset(path: Path) -> List[Dict[str, Any]]:
    import pandas as pd
    df = pd.read_csv(path)
    emails: List[Dict[str, Any]] = []
    for _, row in df.iterrows():
        d = row.to_dict()
        # Ensure required keys presence
        d.setdefault("id", d.get("email_id", str(_)))
        d.setdefault("subject", d.get("subject", ""))
        d.setdefault("body", d.get("body", ""))
        d.setdefault("is_phishing", bool(d.get("is_phishing", False)))
        emails.append(d)
    return emails


def main() -> None:
    _generate_dataset_if_missing(DATASET_PATH)
    emails = _load_dataset(DATASET_PATH)
    if not emails:
        raise SystemExit("No emails loaded; aborting index build")

    logger.info(f"Loaded {len(emails)} emails; starting vector index build")
    builder = VectorIndexBuilder(db_path="data/chroma", collection_name=COLLECTION_NAME)
    stats = builder.build_index(emails)
    logger.info("Index build complete")
    for k, v in stats.items():
        logger.info(f"  - {k}: {v}")


if __name__ == "__main__":
    main()
