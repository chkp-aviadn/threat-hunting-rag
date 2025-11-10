"""
Repository interfaces for data access.

Defines contracts for data access that can be implemented by different storage backends.
"""

from abc import ABC, abstractmethod
from typing import List, Optional

from core.models import Email, SearchResults, SearchQuery


class EmailRepository(ABC):
    """Abstract repository for email data access."""
    
    @abstractmethod
    def get_all_emails(self) -> List[Email]:
        """Get all emails from storage."""
        pass
    
    @abstractmethod
    def get_email_by_id(self, email_id: str) -> Optional[Email]:
        """Get email by ID."""
        pass
    
    @abstractmethod
    def save_email(self, email: Email) -> Email:
        """Save email to storage."""
        pass
    
    @abstractmethod
    def search_emails(self, query: SearchQuery) -> List[Email]:
        """Search emails by query."""
        pass
    
    @abstractmethod
    def count_emails(self) -> int:
        """Get total count of emails."""
        pass


class VectorRepository(ABC):
    """Abstract repository for vector operations."""
    
    @abstractmethod
    def store_embeddings(self, email_ids: List[str], embeddings: List[List[float]], metadata: List[dict]) -> None:
        """Store email embeddings with metadata."""
        pass
    
    @abstractmethod
    def search_similar(self, query_embedding: List[float], limit: int = 10) -> List[dict]:
        """Search for similar embeddings."""
        pass
    
    @abstractmethod
    def get_embedding(self, email_id: str) -> Optional[List[float]]:
        """Get embedding for specific email."""
        pass
    
    @abstractmethod
    def rebuild_index(self) -> None:
        """Rebuild the vector index."""
        pass
