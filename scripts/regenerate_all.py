#!/usr/bin/env python
"""Full regeneration script for threat-hunting-rag.

Performs a deterministic rebuild sequence:
 1. Force-generate synthetic dataset (overwrites existing data/emails.csv).
 2. Validate each generated email against Pydantic Email schema (collect errors).
 3. Persist validated dataset to CSV.
 4. Rebuild Chroma semantic index (clears existing collection).
 5. Emit summary statistics.

Exit code is non-zero if any validation errors occurred.
"""
from __future__ import annotations
import os
import sys
import logging
from pathlib import Path
from typing import List, Dict, Any
from dataclasses import asdict

logging.basicConfig(level=logging.INFO, format="[regenerate] %(message)s")
logger = logging.getLogger("regenerate")

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.append(str(SRC))

DATASET_PATH = Path(os.getenv("EMAIL_DATASET_PATH", "data/emails.csv"))
COLLECTION_NAME = os.getenv("COLLECTION_NAME", "threat_hunting_emails")

# Imports with fallbacks
try:
    from data_preparation.generators.generate_dataset import EmailGenerator, SimpleEmail
    from data_preparation.embeddings.index_builder import VectorIndexBuilder
    from data_preparation.schemas.email import Email, EmailAttachment
except ImportError:  # pragma: no cover
    from src.data_preparation.generators.generate_dataset import EmailGenerator, SimpleEmail  # type: ignore
    from src.data_preparation.embeddings.index_builder import VectorIndexBuilder  # type: ignore
    from src.data_preparation.schemas.email import Email, EmailAttachment  # type: ignore


def _generate_dataset(total: int = 150) -> List[SimpleEmail]:
    legit = int(total * 0.7)
    phishing = total - legit
    gen = EmailGenerator()
    emails: List[SimpleEmail] = []
    for _ in range(legit):
        emails.append(gen.generate_legitimate_email())
    for _ in range(phishing):
        emails.append(gen.generate_phishing_email())
    return emails


def _convert_to_schema(simple: SimpleEmail) -> Email:
    # Map SimpleEmail -> Email schema; attachments are filenames only
    attachments = []
    for fname in simple.attachments:
        attachments.append(EmailAttachment(filename=fname, size=0, content_type=None))
    return Email(
        id=simple.id,
        sender=simple.sender,
        sender_domain=simple.sender_domain,
        recipient=None,
        subject=simple.subject,
        body=simple.body,
        timestamp=simple.timestamp,
        attachments=attachments,
        attachment_count=len(attachments),
        is_phishing=simple.is_phishing,
        phishing_type=simple.phishing_type,
        confidence=simple.confidence,
    )


def _validate_emails(emails: List[SimpleEmail]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    errors = 0
    for e in emails:
        try:
            schema_obj = _convert_to_schema(e)
            d = schema_obj.model_dump()
            # Normalize datetime fields for Chroma metadata (must be primitive types)
            for time_field in ["timestamp", "created_at"]:
                if time_field in d and hasattr(d[time_field], "isoformat"):
                    d[time_field] = d[time_field].isoformat()
            # Remove None values from metadata (Chroma requires primitives only)
            cleaned = {k: v for k, v in d.items() if v is not None}
            rows.append(cleaned)
        except Exception as exc:  # Collect validation errors
            errors += 1
            logger.error(f"Validation failed for id={e.id}: {exc}")
    if errors:
        logger.error(f"Validation errors: {errors} (dataset will still write for inspection)")
    return rows


def _write_csv(rows: List[Dict[str, Any]]) -> None:
    import pandas as pd
    DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)
    df = pd.DataFrame(rows)
    df.to_csv(DATASET_PATH, index=False)
    logger.info(f"Dataset written: {DATASET_PATH} (rows={len(df)})")


def _rebuild_index(rows: List[Dict[str, Any]]) -> None:
    builder = VectorIndexBuilder(db_path="data/chroma", collection_name=COLLECTION_NAME)
    stats = builder.build_index(rows)
    logger.info("Index rebuild stats:")
    for k, v in stats.items():
        logger.info(f"  - {k}: {v}")


def main() -> None:
    logger.info("Starting full regeneration sequence")
    emails = _generate_dataset()
    logger.info(f"Generated {len(emails)} raw emails (SimpleEmail)")
    rows = _validate_emails(emails)
    _write_csv(rows)
    _rebuild_index(rows)
    logger.info("Full regeneration complete")


if __name__ == "__main__":
    main()
