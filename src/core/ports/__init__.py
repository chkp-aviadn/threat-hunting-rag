"""
Port interfaces for the core domain.

Defines contracts that external layers must implement to interact with core business logic.
"""

from .repositories import EmailRepository, VectorRepository

__all__ = [
    # Repository ports
    "EmailRepository",
    "VectorRepository"
]
