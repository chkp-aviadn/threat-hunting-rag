"""
Shared enumerations used across the threat hunting system.

Base enums that define common types and constants used throughout all layers.
"""

from enum import Enum


class ThreatLevel(str, Enum):
    """Threat level classification."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    NEGLIGIBLE = "NEGLIGIBLE"


class SearchMethod(str, Enum):
    """Available search methods."""

    KEYWORD = "keyword"
    SEMANTIC = "semantic"
    HYBRID = "hybrid"


class JobStatus(str, Enum):
    """Job processing status."""

    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


class HealthStatus(str, Enum):
    """System health status."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
