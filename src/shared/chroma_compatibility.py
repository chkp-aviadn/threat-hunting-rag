"""
ChromaDB Compatibility Layer

This module provides compatibility wrappers for ChromaDB to handle version conflicts
and OpenTelemetry issues. It includes fallback mechanisms for various ChromaDB versions
and provides a consistent interface for the RAG system.

If ChromaDB cannot be imported due to SQLite version issues, falls back to a simple
vector store implementation.
"""

# Disable ChromaDB telemetry BEFORE importing chromadb
import os
os.environ.setdefault("CHROMA_TELEMETRY_DISABLED", "TRUE")
os.environ.setdefault("ANONYMIZED_TELEMETRY", "FALSE")

import sys
import warnings
import numpy as np
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Suppress OpenTelemetry warnings for ChromaDB compatibility
warnings.filterwarnings("ignore", category=UserWarning, module="chromadb")


class SimpleVectorStore:
    """Simple vector store with disk persistence as fallback for ChromaDB."""

    def __init__(self, name: str, persist_dir: str = "data/simple_vector_db"):
        self.name = name
        self.persist_dir = Path(persist_dir)
        self.persist_dir.mkdir(parents=True, exist_ok=True)
        self.storage_file = self.persist_dir / f"{name}.pkl"

        # Load existing data if available
        self.embeddings = []
        self.documents = []
        self.metadatas = []
        self.ids = []
        self._load_data()

    def _load_data(self):
        """Load persisted data from disk."""
        try:
            if self.storage_file.exists():
                import pickle

                with open(self.storage_file, "rb") as f:
                    data = pickle.load(f)
                    self.embeddings = data.get("embeddings", [])
                    self.documents = data.get("documents", [])
                    self.metadatas = data.get("metadatas", [])
                    self.ids = data.get("ids", [])
                logger.info(f"Loaded {len(self.documents)} documents from {self.storage_file}")
        except Exception as e:
            logger.warning(f"Could not load data from {self.storage_file}: {e}")

    def _save_data(self):
        """Save data to disk for persistence."""
        try:
            import pickle

            data = {
                "embeddings": self.embeddings,
                "documents": self.documents,
                "metadatas": self.metadatas,
                "ids": self.ids,
            }
            with open(self.storage_file, "wb") as f:
                pickle.dump(data, f)
            logger.debug(f"Saved {len(self.documents)} documents to {self.storage_file}")
        except Exception as e:
            logger.error(f"Could not save data to {self.storage_file}: {e}")

    def add(
        self,
        embeddings: List[List[float]],
        documents: List[str],
        metadatas: List[Dict],
        ids: List[str],
    ):
        """Add documents to the vector store."""
        self.embeddings.extend(embeddings)
        self.documents.extend(documents)
        self.metadatas.extend(metadatas)
        self.ids.extend(ids)
        self._save_data()  # Save after adding
        logger.info(f"Added {len(documents)} documents to SimpleVectorStore '{self.name}'")

    def query(
        self,
        query_embeddings: List[List[float]],
        n_results: int = 5,
        where: Optional[Dict] = None,
        **kwargs,
    ) -> Dict:
        """Query the vector store for similar documents."""
        if not self.embeddings:
            return {"ids": [[]], "distances": [[]], "metadatas": [[]], "documents": [[]]}

        # Simple cosine similarity
        query_emb = np.array(query_embeddings[0])
        similarities = []

        for emb in self.embeddings:
            doc_emb = np.array(emb)
            similarity = np.dot(query_emb, doc_emb) / (
                np.linalg.norm(query_emb) * np.linalg.norm(doc_emb)
            )
            similarities.append(similarity)

        # Get top n_results
        indices = np.argsort(similarities)[::-1][:n_results]

        # Build result ensuring all arrays have same length
        result_ids = [self.ids[i] for i in indices if i < len(self.ids)]
        result_distances = [1 - similarities[i] for i in indices if i < len(similarities)]
        result_metadatas = [self.metadatas[i] for i in indices if i < len(self.metadatas)]
        result_documents = [self.documents[i] for i in indices if i < len(self.documents)]

        result = {
            "ids": [result_ids],
            "distances": [result_distances],
            "metadatas": [result_metadatas],
            "documents": [result_documents],
        }

        logger.debug(f"SimpleVectorStore query returned {len(result['ids'][0])} results")
        return result

    def count(self) -> int:
        """Return number of documents in the store."""
        return len(self.documents)

    def get(self, ids: Optional[List[str]] = None, where: Optional[Dict] = None, **kwargs) -> Dict:
        """Get documents from the store (ChromaDB compatibility method)."""
        if ids:
            # Return specific documents by ID
            result_ids = []
            result_docs = []
            result_metadatas = []

            for id_to_find in ids:
                if id_to_find in self.ids:
                    idx = self.ids.index(id_to_find)
                    result_ids.append(self.ids[idx])
                    result_docs.append(self.documents[idx])
                    result_metadatas.append(self.metadatas[idx])

            return {"ids": result_ids, "documents": result_docs, "metadatas": result_metadatas}
        else:
            # Return all documents
            return {"ids": self.ids, "documents": self.documents, "metadatas": self.metadatas}


class SimpleVectorClient:
    """Simple client that mimics ChromaDB interface."""

    def __init__(self, persist_directory: str = "data/simple_vector_db"):
        self.collections = {}
        self.persist_directory = persist_directory
        logger.info("Created SimpleVectorClient as ChromaDB fallback")

    def get_collection(self, name: str):
        """Get existing collection."""
        if name not in self.collections:
            raise ValueError(f"Collection {name} does not exist")
        return self.collections[name]

    def create_collection(
        self, name: str, metadata: Optional[Dict] = None, embedding_function=None, **kwargs
    ):
        """Create a new collection."""
        collection = SimpleVectorStore(name, self.persist_directory)
        # Store embedding function if provided (for compatibility)
        if embedding_function:
            collection.embedding_function = embedding_function
        self.collections[name] = collection
        logger.info(f"Created SimpleVectorStore collection '{name}'")
        return collection


def get_compatible_chroma_client(
    persist_directory: str = "./data/chroma", collection_name: str = "threat_hunting_emails"
) -> tuple:
    """Get a ChromaDB client compatible with current environment."""
    try:
        # Try to use pysqlite3-binary if available
        try:
            import pysqlite3.dbapi2 as sqlite3
            import sys

            sys.modules["sqlite3"] = sqlite3
        except ImportError:
            pass

        # Try importing ChromaDB
        import chromadb
        from chromadb.config import Settings

        logger.info("ChromaDB import successful")

        settings = create_chroma_settings(persist_directory)
        client = create_chroma_client(persist_directory, settings)

        try:
            collection = client.get_collection(collection_name)
            logger.info(f"Found existing ChromaDB collection '{collection_name}'")
        except Exception:
            # Collection doesn't exist, create it
            collection = client.create_collection(
                name=collection_name, metadata={"hnsw:space": "cosine"}
            )
            logger.info(f"Created new ChromaDB collection '{collection_name}'")

        return client, collection

    except Exception as e:
        # ChromaDB failed to import or initialize, use simple fallback
        logger.warning(f"ChromaDB unavailable ({e}), using simple vector store fallback")

        # Use simple_vector_db subdirectory to match production behavior
        simple_persist_dir = str(Path(persist_directory).parent / "simple_vector_db")
        client = SimpleVectorClient(simple_persist_dir)
        try:
            collection = client.get_collection(collection_name)
        except ValueError:
            collection = client.create_collection(collection_name)

        return client, collection


def create_chroma_settings(persist_directory: str = "./data/chroma"):
    """Create ChromaDB settings with compatibility patches."""
    try:
        from chromadb.config import Settings

        return Settings(anonymized_telemetry=False, allow_reset=True)
    except Exception as e:
        # Fallback for different ChromaDB versions
        logger.debug(f"Using fallback settings due to: {e}")
        return {"anonymized_telemetry": False, "allow_reset": True}


def create_chroma_client(persist_directory: str, settings: Any):
    """Create ChromaDB client with compatibility handling."""
    try:
        import chromadb

        # Try persistent client first
        try:
            client = chromadb.PersistentClient(path=persist_directory)
            logger.info(f"Created ChromaDB PersistentClient at {persist_directory}")
            return client
        except Exception as e1:
            logger.debug(f"PersistentClient failed: {e1}")

            # Try older client creation method
            try:
                client = chromadb.Client(settings)
                logger.info("Created ChromaDB Client with settings")
                return client
            except Exception as e2:
                logger.debug(f"Client with settings failed: {e2}")

                # Last resort: in-memory client
                client = chromadb.Client()
                logger.info("Created ChromaDB in-memory client")
                return client

    except Exception as e:
        logger.error(f"Failed to create ChromaDB client: {e}")
        raise e


# Handle OpenTelemetry compatibility issues
try:
    from opentelemetry.attributes import BoundedAttributes
except ImportError:
    # Create a mock BoundedAttributes if it's missing
    class BoundedAttributes(dict):
        def __init__(self, attributes=None, max_len=128):
            super().__init__(attributes or {})
            self.max_len = max_len

    # Monkey patch it into the opentelemetry.attributes module
    try:
        import opentelemetry.attributes

        opentelemetry.attributes.BoundedAttributes = BoundedAttributes
        logger.debug("Monkey-patched BoundedAttributes for ChromaDB compatibility")
    except ImportError:
        logger.debug("OpenTelemetry not available, BoundedAttributes patch not needed")
