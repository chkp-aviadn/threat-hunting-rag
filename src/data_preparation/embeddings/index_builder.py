"""
Vector Index Builder for Threat Hunting RAG System

This module implements the vector index builder using Chroma as specified
in Phase 3, Task 3.2 of the plan.md.

Requirements from plan.md:
- Create persistent Chroma vector database
- Store embeddings with metadata
- Build searchable index at data/chroma/
- Build time < 30 seconds for 150 emails
"""

import os
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path
import pandas as pd

import numpy as np
import sys
import os

# Add shared to path for compatibility wrapper
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "..", "shared"))

from chroma_compatibility import (
    get_compatible_chroma_client,
    create_chroma_settings,
    create_chroma_client,
)
from .embeddings import EmbeddingGenerator

logger = logging.getLogger(__name__)


class VectorIndexBuilder:
    """
    Builds and manages Chroma vector database for email semantic search.

    Features:
    - Persistent storage to data/chroma/
    - Metadata preservation for emails
    - Efficient batch processing
    - Searchable semantic index
    """

    def __init__(self, db_path: str = "data/chroma", collection_name: str = "threat_hunting_emails"):
        """
        Initialize the vector index builder.

        Args:
            db_path: Path to store Chroma database
            collection_name: Name of the collection for emails
        """
        self.db_path = Path(db_path)
        # Normalize collection name across system (unified with provider and search services)
        if collection_name != "threat_hunting_emails":
            logger.debug(
                f"Overriding provided collection_name '{collection_name}' to canonical 'threat_hunting_emails'"
            )
            collection_name = "threat_hunting_emails"
        self.collection_name = collection_name
        self.client = None
        self.collection = None
        self.embedding_generator = EmbeddingGenerator()

        # Create database directory
        self.db_path.mkdir(parents=True, exist_ok=True)

        logger.info(f"Initialized VectorIndexBuilder at {self.db_path}")

    def _get_client(self):
        """Get or create Chroma client with persistent storage."""
        if self.client is None:
            # Use absolute path to avoid environment-dependent relative path permission issues (test runner mounts)
            persist_path = str(self.db_path.resolve())
            logger.info(f"Creating Chroma client with persistence at {persist_path}")

            try:
                client, _ = get_compatible_chroma_client(
                    persist_directory=persist_path,
                    collection_name="temp",  # We'll create the real collection later
                )
                self.client = client
                logger.info(
                    "✅ ChromaDB client created successfully with compatibility wrapper"
                )
            except Exception as e:
                logger.error(f"Failed to create ChromaDB client: {e}")
                raise RuntimeError(f"ChromaDB initialization failed: {e}")

        return self.client

    def _get_collection(self):
        """Get or create the email collection."""
        if self.collection is None:
            client = self._get_client()

            try:
                # Try to get existing collection
                self.collection = client.get_collection(name=self.collection_name)
                logger.info(f"Loaded existing collection: {self.collection_name}")
            except Exception:
                # Create new collection if it doesn't exist (broadened exception for chroma variants)
                logger.info(f"Creating new collection: {self.collection_name}")
                self.collection = client.create_collection(
                    name=self.collection_name,
                    embedding_function=None,  # We'll provide embeddings manually
                )
                logger.info(f"Created collection: {self.collection_name}")

        return self.collection

    def build_index(self, emails: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Build vector index from email dataset.

        Args:
            emails: List of email dictionaries with required fields

        Returns:
            Dictionary with build statistics
        """
        if not emails:
            raise ValueError("Email list cannot be empty")

        logger.info(f"Building vector index for {len(emails)} emails...")
        start_time = pd.Timestamp.now()

        # Get collection
        collection = self._get_collection()

        # Check if collection already has data
        existing_count = collection.count()
        if existing_count > 0:
            logger.warning(f"Collection already contains {existing_count} documents. Clearing...")
            # Delete collection and recreate
            client = self._get_client()
            client.delete_collection(self.collection_name)
            self.collection = None
            collection = self._get_collection()

        # Prepare data for batch insertion
        documents = []
        metadatas = []
        ids = []

        for i, email in enumerate(emails):
            # Create document text (subject + body)
            subject = email.get("subject", "")
            body = email.get("body", "")
            document_text = f"{subject}\n\n{body}".strip()

            # Create metadata (preserve all fields except embeddings)
            metadata = {
                "email_id": email.get("id", f"email_{i}"),
                "subject": subject,
                "sender": email.get("sender", ""),
                "recipient": email.get("recipient", ""),
                "timestamp": email.get("timestamp", ""),
                "category": email.get("category", "unknown"),
                "is_phishing": email.get("is_phishing", False),
                "confidence_score": email.get("confidence_score", 0.0),
                "attachments": email.get("attachments", ""),
                "attachment_count": email.get("attachment_count", 0),
                "phishing_type": email.get("phishing_type", ""),
                "confidence": email.get("confidence", 0.0),
                "index": i,
            }

            # Add any additional metadata fields
            for key, value in email.items():
                if key not in ["body", "embedding"] and key not in metadata:
                    if isinstance(value, (str, int, float, bool)):
                        metadata[key] = value

            documents.append(document_text)
            metadatas.append(metadata)
            ids.append(f"email_{i}")

        # Generate embeddings in batches
        logger.info("Generating embeddings...")
        embeddings = []

        # Process emails to get combined text for embeddings
        email_texts = []
        for email in emails:
            subject = email.get("subject", "")
            body = email.get("body", "")
            combined_text = f"{subject}\n\n{body}".strip()
            email_texts.append(combined_text)

        # Generate embeddings using our EmbeddingGenerator
        embeddings_list = self.embedding_generator.embed_batch(email_texts, batch_size=32)

        # Convert to list format for Chroma
        embeddings = [embedding.tolist() for embedding in embeddings_list]

        # Add to collection in batches
        batch_size = 100
        logger.info(f"Adding {len(documents)} documents to collection...")

        for i in range(0, len(documents), batch_size):
            end_idx = min(i + batch_size, len(documents))
            batch_documents = documents[i:end_idx]
            batch_metadatas = metadatas[i:end_idx]
            batch_ids = ids[i:end_idx]
            batch_embeddings = embeddings[i:end_idx]

            logger.info(f"Adding batch {i//batch_size + 1}/{(len(documents)-1)//batch_size + 1}")

            collection.add(
                documents=batch_documents,
                metadatas=batch_metadatas,
                ids=batch_ids,
                embeddings=batch_embeddings,
            )

        # Persist the database (newer versions auto-persist)
        try:
            client = self._get_client()
            if hasattr(client, "persist"):
                client.persist()
                logger.info("ChromaDB data persisted explicitly")
            else:
                logger.info("ChromaDB using auto-persistence (newer version)")
        except Exception as e:
            logger.warning(f"Persistence method not available: {e}")
            # Newer ChromaDB versions auto-persist

        # Calculate statistics
        end_time = pd.Timestamp.now()
        build_time = (end_time - start_time).total_seconds()

        stats = {
            "total_emails": len(emails),
            "build_time_seconds": build_time,
            "collection_name": self.collection_name,
            "db_path": str(self.db_path),
            "embedding_dimension": len(embeddings[0]) if embeddings else 0,
            "collection_count": collection.count(),
        }

        logger.info(f"✅ Index built successfully!")
        logger.info(f"   Total emails: {stats['total_emails']}")
        logger.info(f"   Build time: {build_time:.1f} seconds")
        logger.info(f"   Database path: {stats['db_path']}")
        logger.info(f"   Collection size: {stats['collection_count']}")

        return stats

    def search(
        self, query_text: str, n_results: int = 10, where_filter: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Search the vector index for similar emails.

        Args:
            query_text: Search query text
            n_results: Number of results to return
            where_filter: Optional metadata filter

        Returns:
            Dictionary with search results
        """
        collection = self._get_collection()

        # Generate embedding for query
        query_embedding = self.embedding_generator.embed_text(query_text)

        # Perform search
        results = collection.query(
            query_embeddings=[query_embedding.tolist()],
            n_results=n_results,
            where=where_filter,
            include=["documents", "metadatas", "distances"],
        )

        return {
            "query": query_text,
            "results": results,
            "n_results": len(results["ids"][0]) if results["ids"] else 0,
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        try:
            collection = self._get_collection()
            count = collection.count()

            return {
                "collection_name": self.collection_name,
                "document_count": count,
                "db_path": str(self.db_path),
                "db_exists": self.db_path.exists(),
                "embedding_dimension": self.embedding_generator.get_embedding_dimension(),
            }
        except Exception as e:
            logger.error(f"Failed to get stats: {e}")
            return {
                "error": str(e),
                "db_path": str(self.db_path),
                "db_exists": self.db_path.exists(),
            }

    def clear_index(self) -> None:
        """Clear the vector index."""
        if self.client and self.collection:
            try:
                self.client.delete_collection(self.collection_name)
                self.collection = None
                logger.info(f"Cleared collection: {self.collection_name}")
            except Exception as e:
                logger.warning(f"Failed to clear collection: {e}")


def test_vector_index():
    """Test function to verify vector index works correctly."""
    logger.info("Testing Chroma vector index...")

    # Create test emails
    test_emails = [
        {
            "id": "email_1",
            "subject": "Urgent payment required",
            "body": "Your account will be suspended unless you pay immediately. Click here to update payment.",
            "sender": "billing@suspicious-bank.com",
            "recipient": "user@company.com",
            "timestamp": "2024-01-01T10:00:00Z",
            "category": "phishing",
            "is_phishing": True,
            "confidence_score": 0.95,
        },
        {
            "id": "email_2",
            "subject": "Team meeting tomorrow",
            "body": "Don't forget about our weekly team meeting at 2 PM in conference room A.",
            "sender": "manager@company.com",
            "recipient": "team@company.com",
            "timestamp": "2024-01-01T11:00:00Z",
            "category": "legitimate",
            "is_phishing": False,
            "confidence_score": 0.1,
        },
        {
            "id": "email_3",
            "subject": "IMMEDIATE ACTION REQUIRED",
            "body": "Your PayPal account has been compromised. Verify identity now or lose access forever!",
            "sender": "security@fake-paypal.com",
            "recipient": "user@company.com",
            "timestamp": "2024-01-01T12:00:00Z",
            "category": "phishing",
            "is_phishing": True,
            "confidence_score": 0.88,
        },
    ]

    # Initialize builder
    builder = VectorIndexBuilder(db_path="test_data/chroma")

    # Build index
    stats = builder.build_index(test_emails)
    logger.info(f"✅ Index built: {stats}")

    # Test search
    search_results = builder.search("urgent payment account", n_results=2)
    logger.info("✅ Search results for 'urgent payment account':")
    for i, (doc, metadata, distance) in enumerate(
        zip(
            search_results["results"]["documents"][0],
            search_results["results"]["metadatas"][0],
            search_results["results"]["distances"][0],
        )
    ):
        logger.info(f"  {i+1}. Subject: {metadata['subject']} (distance: {distance:.3f})")
        logger.info(f"     Category: {metadata['category']}, Phishing: {metadata['is_phishing']}")

    # Test filtering
    phishing_results = builder.search(
        "account security", n_results=5, where_filter={"is_phishing": True}
    )
    logger.info(f"✅ Phishing-only search results: {phishing_results['n_results']} found")

    # Get stats
    db_stats = builder.get_stats()
    logger.info(f"✅ Database stats: {db_stats}")

    logger.info("✅ Vector index test completed successfully!")


if __name__ == "__main__":
    test_vector_index()
