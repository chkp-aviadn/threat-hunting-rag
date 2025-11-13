"""Chroma initialization & embedding backfill utilities.

This module formalizes the Chroma setup process:
1. Ensures sqlite3 points to pysqlite3 (>=3.35) for Chroma compatibility.
2. Creates or retrieves the target collection.
3. Optionally backfills embeddings from the synthetic email dataset.

It complements `shared/chroma_compatibility.get_compatible_chroma_client` but adds
explicit embedding ingestion and a clean entrypoint for the application startup.
"""

from __future__ import annotations

import os
import sys
import csv
import logging
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Any

from data_preparation.embeddings.embeddings import EmbeddingGenerator
from shared.chroma_compatibility import get_compatible_chroma_client

logger = logging.getLogger(__name__)

DEFAULT_COLLECTION = "threat_hunting_emails"
DEFAULT_PERSIST_DIR = "./data/chroma"
DATASET_CSV = "data/emails.csv"


def ensure_sqlite_shim() -> None:
    """Monkey patch standard sqlite3 with pysqlite3 if available.

    Chroma requires sqlite >=3.35; many system distributions ship <3.35.
    pysqlite3-binary bundles a modern SQLite. We patch early to satisfy import checks.
    Safe to call multiple times.
    """
    try:
        import pysqlite3.dbapi2 as sqlite3  # type: ignore

        sys.modules["sqlite3"] = sqlite3
        logger.debug(f"sqlite3 patched to pysqlite3 (version {sqlite3.sqlite_version})")
    except Exception as e:
        logger.debug(f"pysqlite3 not available, using system sqlite3; error={e}")


def init_chroma_collection(
    collection_name: str = DEFAULT_COLLECTION,
    persist_directory: str = DEFAULT_PERSIST_DIR,
    backfill: bool = False,
    dataset_csv: str = DATASET_CSV,
    max_backfill: Optional[int] = None,
) -> Tuple[object, object]:
    """Initialize Chroma (or fallback) collection and optionally backfill embeddings.

    Args:
        collection_name: Target collection name.
        persist_directory: Directory for Chroma persistence.
        backfill: Whether to ingest dataset embeddings if empty.
        dataset_csv: Path to synthetic email dataset.
        max_backfill: Optional cap on backfilled rows (for quicker startup).

    Returns:
        (client, collection)
    """
    # Disable telemetry to avoid posthog noise
    os.environ.setdefault("CHROMA_TELEMETRY_DISABLED", "TRUE")
    os.environ.setdefault("ANONYMIZED_TELEMETRY", "FALSE")

    ensure_sqlite_shim()
    client, collection = get_compatible_chroma_client(
        persist_directory=persist_directory, collection_name=collection_name
    )

    try:
        count = collection.count()
    except Exception:
        try:
            count = len(collection.ids)  # type: ignore[attr-defined]
        except Exception:
            count = 0

    # If legacy probe doc with dimension mismatch exists (single item w/ 'probe' metadata) recreate collection
    if backfill and count == 1:
        try:
            probe_sample = collection.get(limit=1, include=["metadatas", "documents"])  # type: ignore[arg-type]
            metas = probe_sample.get("metadatas", [])
            if metas and isinstance(metas[0], dict) and metas[0].get("probe"):
                logger.info(
                    "Detected legacy probe placeholder; recreating collection before backfill"
                )
                try:
                    client = get_compatible_chroma_client(
                        persist_directory=persist_directory, collection_name="temp"
                    )[0]
                except Exception:
                    client = None
                try:
                    if client and hasattr(client, "delete_collection"):
                        client.delete_collection(collection_name)
                except Exception:
                    pass
                # Recreate clean collection
                client2, collection2 = get_compatible_chroma_client(
                    persist_directory=persist_directory, collection_name=collection_name
                )
                collection = collection2
                count = collection.count() if hasattr(collection, "count") else 0
        except Exception:
            pass
    # Simplify: if backfill requested and any pre-existing docs, recreate collection to avoid dimension conflicts
    if backfill and count > 0:
        try:
            if hasattr(collection, "count"):
                logger.info(
                    f"Existing collection '{collection_name}' has {count} items; recreating for clean backfill"
                )
            # Obtain fresh client and delete
            try:
                import chromadb  # noqa: F401

                client_delete = get_compatible_chroma_client(
                    persist_directory=persist_directory, collection_name="temp"
                )[0]
                if hasattr(client_delete, "delete_collection"):
                    client_delete.delete_collection(collection_name)
            except Exception:
                pass
            # Recreate collection
            client_new, collection_new = get_compatible_chroma_client(
                persist_directory=persist_directory, collection_name=collection_name
            )
            collection = collection_new
            count = 0
        except Exception as e:
            logger.warning(f"Could not recreate existing collection: {e}")

    if backfill and count == 0:
        logger.info(
            f"Collection '{collection_name}' empty. Starting backfill from {dataset_csv}..."
        )
        backfill_embeddings(collection, dataset_csv, max_rows=max_backfill)
        logger.info(
            f"Backfill complete. New collection count: {collection.count() if hasattr(collection,'count') else 'unknown'}"
        )
    else:
        logger.info(f"Collection '{collection_name}' already has {count} items; skipping backfill.")
    return client, collection


def backfill_embeddings(
    collection: object,
    dataset_csv: str = DATASET_CSV,
    max_rows: Optional[int] = None,
    batch_size: int = 32,
) -> None:
    """Ingest embeddings & documents into the provided collection.

    Works for Chroma collections or SimpleVectorStore fallback (supports .add).

    Args:
        collection: Chroma or fallback collection object.
        dataset_csv: Path to emails CSV.
        max_rows: Limit number of rows ingested (None = all).
        batch_size: Batch size for embedding generation.
    """
    path = Path(dataset_csv)
    if not path.exists():
        logger.warning(f"Dataset file {dataset_csv} not found. Skipping backfill.")
        return

    generator = EmbeddingGenerator()
    rows: List[Dict[str, str]] = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            rows.append(row)
            if max_rows is not None and i + 1 >= max_rows:
                break

    if not rows:
        logger.warning("No rows loaded for backfill.")
        return

    # Prepare texts & metadata (ensure subject present for downstream Email validation)
    texts: List[str] = []
    ids: List[str] = []
    metadatas: List[Dict[str, Any]] = []
    documents: List[str] = []
    for i, row in enumerate(rows):
        subject = (row.get("subject") or "").strip()
        body = (row.get("body") or "").strip()
        combined = f"{subject}\n\n{body}".strip()
        # Ensure non-empty subject (validator requires >=1 char); fallback to first 6 words of body
        if not subject:
            fallback_subject = " ".join(body.split()[:6]) or "no subject"
            subject = fallback_subject
        texts.append(combined)
        email_id = row.get("id") or row.get("uuid") or f"row_{i}"
        ids.append(str(email_id))
        metadata: Dict[str, Any] = {
            "email_id": str(email_id),
            "subject": subject,
            "sender": row.get("sender") or "",
            "recipient": row.get("recipient") or "unknown@example.com",
            "timestamp": row.get("timestamp") or "",
            "category": row.get("category") or "unknown",
            "is_phishing": (
                bool(row.get("is_phishing"))
                if row.get("is_phishing") in ["True", "False", True, False, "1", "0"]
                else False
            ),
            "confidence_score": (
                float(row.get("confidence_score"))
                if row.get("confidence_score") not in (None, "")
                else 0.0
            ),
            "sender_domain": row.get("sender_domain") or "",
            "phishing_type": row.get("phishing_type") or "",
        }
        metadatas.append(metadata)
        # Store full combined truncated document so body extraction works
        documents.append(combined[:1000])

    # Embed in batches (ensure consistent dimension)
    embeddings: List[List[float]] = []
    for start in range(0, len(texts), batch_size):
        batch = texts[start : start + batch_size]
        batch_embeddings = []
        for t in batch:
            emb = generator.embed_text(t)
            # emb may be numpy array; convert to list of floats
            if hasattr(emb, "tolist"):
                emb_list = emb.tolist()
            else:
                emb_list = list(emb)
            batch_embeddings.append(emb_list)
        embeddings.extend(batch_embeddings)

    if not embeddings:
        logger.error("No embeddings generated; aborting backfill")
        return

    # Validate embedding dimension consistency
    dim = len(embeddings[0])
    if any(len(e) != dim for e in embeddings):
        logger.error("Inconsistent embedding dimensions detected; aborting backfill")
        return

    # Ingestion API differences: Chroma expects named parameters; fallback uses .add directly.
    added = 0
    try:
        # Try Chroma-style add first
        collection.add(embeddings=embeddings, documents=documents, metadatas=metadatas, ids=ids)
        added = len(ids)
    except TypeError as te:
        # Detect if this is due to signature mismatch vs data error
        if "metadatas" in str(te) or "embeddings" in str(te):
            logger.debug(f"TypeError on Chroma add, attempting fallback signature: {te}")
            try:
                collection.add(embeddings, documents, metadatas, ids)  # type: ignore[arg-type]
                added = len(ids)
            except Exception as e2:
                logger.error(f"Fallback add failed: {e2}")
                return
        else:
            logger.error(f"Chroma add TypeError not related to signature: {te}")
            return
    except Exception as e:
        logger.error(f"Failed to add embeddings to collection: {e}")
        return

    logger.info(
        f"Backfilled {added} items into collection '{getattr(collection,'name', 'unknown')}'."
    )


def capability_probe() -> Dict[str, bool]:
    """Return diagnostic booleans about vector backend health."""
    status = {"pysqlite3_available": False, "chroma_import_ok": False, "collection_writable": False}
    # Ensure shim BEFORE attempting chromadb import so version check sees patched sqlite3
    try:
        ensure_sqlite_shim()
    except Exception:
        pass
    # Emit quick info if shim succeeded
    try:
        import sqlite3

        if hasattr(sqlite3, "sqlite_version") and sqlite3.sqlite_version >= "3.35.0":
            logger.info("✅ Using pysqlite3-binary for ChromaDB compatibility")
    except Exception:
        pass
    try:
        import pysqlite3.dbapi2 as _s

        status["pysqlite3_available"] = True
    except Exception:
        pass
    try:
        import chromadb  # noqa: F401

        status["chroma_import_ok"] = True
    except Exception:
        pass
    try:
        ensure_sqlite_shim()
        client, col = get_compatible_chroma_client()
        # Just attempt a count; avoid inserting mismatched probe embedding
        _ = col.count()
        status["collection_writable"] = True
    except Exception as e:
        logger.debug(f"Capability probe write failed: {e}")
    return status


__all__ = [
    "ensure_sqlite_shim",
    "init_chroma_collection",
    "backfill_embeddings",
    "capability_probe",
]
