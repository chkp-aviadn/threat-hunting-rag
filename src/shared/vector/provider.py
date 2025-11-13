"""Unified vector backend provider.

Chooses Chroma collection if healthy, otherwise returns fallback SimpleVectorStore.
Relies on chroma_init utilities and compatibility layer.
"""

import logging
from typing import Tuple, Dict

from shared.vector.chroma_init import init_chroma_collection, capability_probe

logger = logging.getLogger(__name__)


def get_vector_backend(
    collection_name: str = "threat_hunting_emails", backfill: bool = False
) -> Tuple[object, object, Dict[str, bool]]:
    """Return (client, collection, diagnostics)."""
    diagnostics = capability_probe()
    use_chroma = (
        diagnostics["chroma_import_ok"]
        and diagnostics["pysqlite3_available"]
        and diagnostics["collection_writable"]
    )
    if not use_chroma:
        logger.warning(
            f"Chroma not fully healthy (diagnostics={diagnostics}); will attempt fallback or partial mode."
        )
    client, collection = init_chroma_collection(collection_name=collection_name, backfill=backfill)
    return client, collection, diagnostics


__all__ = ["get_vector_backend"]
