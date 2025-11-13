"""
API schemas and response models for the Threat Hunting RAG API.

Defines Pydantic models for request/response validation, OpenAPI documentation,
and type safety across the API endpoints.
"""

import logging
from datetime import datetime
from typing import List, Dict, Optional, Any, Union
from shared.pydantic_compat import BaseModel, Field, field_validator as validator

try:
    # Pydantic v2 ConfigDict (available when using pydantic>=2 and our compat layer may expose it)
    from pydantic import ConfigDict  # type: ignore
except ImportError:  # Fallback: define a minimal shim so code still runs under older compat

    class ConfigDict(dict):  # type: ignore
        pass


from enum import Enum

import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), "..", ".."))

from shared.enums import SearchMethod, ThreatLevel

logger = logging.getLogger(__name__)


class ApiErrorResponse(BaseModel):
    """Standard error response format."""

    error: str = Field(..., description="Error message")
    status_code: int = Field(..., description="HTTP status code")
    timestamp: datetime = Field(..., description="Error timestamp")
    path: str = Field(..., description="API endpoint path")
    details: Optional[Dict[str, Any]] = Field(default=None, description="Additional error details")


class ThreatEmailResult(BaseModel):
    """Individual email result with threat analysis."""

    email_id: str = Field(..., description="Unique email identifier")
    rank: int = Field(..., description="Result ranking (1-based)")

    # Email metadata
    sender: str = Field(..., description="Email sender address")
    recipient: str = Field(..., description="Email recipient address")
    subject: str = Field(..., description="Email subject line")
    body_preview: str = Field(..., description="Email body preview (first 200 chars)")
    timestamp: datetime = Field(..., description="Email timestamp")
    attachments: List[str] = Field(default_factory=list, description="Attachment filenames")

    # Threat analysis
    threat_score: float = Field(..., ge=0.0, le=1.0, description="Overall threat score")
    threat_level: ThreatLevel = Field(..., description="Categorical threat level")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Analysis confidence")
    explanation: str = Field(..., description="Human-readable threat explanation")

    # Search relevance
    search_score: float = Field(..., ge=0.0, le=1.0, description="Search relevance score")
    matched_keywords: List[str] = Field(default_factory=list, description="Matched query keywords")
    semantic_similarity: Optional[float] = Field(
        None, ge=0.0, le=1.0, description="Semantic similarity score"
    )

    # Feature breakdown
    features: Dict[str, float] = Field(..., description="Threat feature scores")

    # Pydantic v2 style configuration
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email_id": "email_145",
                "rank": 1,
                "sender": "finance-urgent@suspicious-domain.co",
                "recipient": "admin@company.com",
                "subject": "URGENT: Payment Required - Account Suspension",
                "body_preview": "Dear Customer, Your account requires immediate payment or it will be suspended...",
                "timestamp": "2024-11-08T14:23:45Z",
                "attachments": ["invoice_urgent.exe"],
                "threat_score": 0.92,
                "threat_level": "HIGH",
                "confidence": 0.89,
                "explanation": "High-risk phishing: urgent language (0.9) + executable attachment (0.95)",
                "search_score": 0.87,
                "matched_keywords": ["urgent", "payment", "suspended"],
                "semantic_similarity": 0.85,
                "features": {
                    "urgent_language": 0.9,
                    "suspicious_attachment": 0.95,
                    "executive_impersonation": 0.1,
                    "new_sender": 0.8,
                },
            }
        }
    )


class SearchMetadata(BaseModel):
    """Metadata about the search operation."""

    method: str = Field(..., description="Search method used")
    keyword_matches: int = Field(default=0, description="Number of keyword matches found")
    semantic_matches: int = Field(default=0, description="Number of semantic matches found")
    cache_hit: bool = Field(default=False, description="Whether result was served from cache")
    components_used: List[str] = Field(default_factory=list, description="Pipeline components used")
    index_searched: str = Field(default="emails", description="Search index used")


class ThreatHuntingResponse(BaseModel):
    """Complete response for threat hunting queries."""

    request_id: str = Field(..., description="Unique request identifier")
    query: str = Field(..., description="Original query text")
    processing_time_ms: int = Field(..., description="Total processing time in milliseconds")
    total_results: int = Field(..., description="Total number of results found")
    results: List[ThreatEmailResult] = Field(..., description="Ranked threat analysis results")
    search_metadata: SearchMetadata = Field(..., description="Search operation metadata")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "request_id": "req_abc123",
                "query": "urgent payment requests from new senders",
                "processing_time_ms": 1250,
                "total_results": 3,
                "results": [
                    # ThreatEmailResult example would go here
                ],
                "search_metadata": {
                    "method": "hybrid",
                    "keyword_matches": 5,
                    "semantic_matches": 8,
                    "cache_hit": False,
                    "components_used": ["retrieval", "analysis", "scoring", "explanation"],
                },
            }
        }
    )


class BatchQueryRequest(BaseModel):
    """Individual query in a batch request."""

    query: str = Field(..., min_length=1, max_length=500, description="Query text")
    max_results: int = Field(default=10, ge=1, le=100, description="Maximum results")
    search_method: SearchMethod = Field(default=SearchMethod.HYBRID, description="Search method")
    threat_threshold: Optional[float] = Field(
        default=None, ge=0.0, le=1.0, description="Threat score threshold"
    )


class BatchQueryResult(BaseModel):
    """Result for individual query in batch processing."""

    query_index: int = Field(..., description="Index of query in batch")
    query: str = Field(..., description="Original query text")
    total_results: int = Field(..., description="Number of results found")
    results: List[ThreatEmailResult] = Field(..., description="Query results")
    processing_time_ms: int = Field(..., description="Processing time for this query")
    error: Optional[str] = Field(default=None, description="Error message if query failed")


class BatchResponse(BaseModel):
    """Response for batch query processing."""

    batch_id: str = Field(..., description="Unique batch identifier")
    total_queries: int = Field(..., description="Total number of queries in batch")
    successful_queries: int = Field(..., description="Number of successfully processed queries")
    processing_time_ms: int = Field(..., description="Total batch processing time")
    results: List[BatchQueryResult] = Field(..., description="Results for each query")


class JobStatus(str, Enum):
    """Async job status values."""

    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


class AsyncJobResponse(BaseModel):
    """Response for async job creation."""

    job_id: str = Field(..., description="Unique job identifier")
    status: JobStatus = Field(..., description="Current job status")
    estimated_completion_seconds: int = Field(..., description="Estimated completion time")
    status_url: str = Field(..., description="URL to check job status")
    priority: int = Field(default=5, description="Job priority level")


class JobStatusResponse(BaseModel):
    """Response for job status checks."""

    job_id: str = Field(..., description="Job identifier")
    status: JobStatus = Field(..., description="Current status")
    progress: int = Field(..., ge=0, le=100, description="Completion percentage")
    created_at: datetime = Field(..., description="Job creation timestamp")
    started_at: Optional[datetime] = Field(default=None, description="Processing start time")
    completed_at: Optional[datetime] = Field(default=None, description="Completion timestamp")
    results: Optional[ThreatHuntingResponse] = Field(
        default=None, description="Results if completed"
    )
    error_message: Optional[str] = Field(default=None, description="Error message if failed")
    estimated_remaining_seconds: Optional[int] = Field(
        default=None, description="Estimated time remaining"
    )


class ComponentHealth(str, Enum):
    """Health status values for system components."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class SystemPerformance(BaseModel):
    """System performance metrics."""

    avg_response_time_ms: float = Field(..., description="Average response time in milliseconds")
    total_queries: int = Field(..., description="Total queries processed")
    cache_hit_rate: float = Field(..., ge=0.0, le=1.0, description="Cache hit rate")
    active_async_jobs: int = Field(..., description="Number of active async jobs")
    queries_per_minute: float = Field(default=0, description="Current query rate")
    error_rate: float = Field(default=0, ge=0.0, le=1.0, description="Error rate in last hour")


class HealthResponse(BaseModel):
    """System health check response."""

    status: ComponentHealth = Field(..., description="Overall system health")
    version: str = Field(..., description="API version")
    uptime_seconds: int = Field(..., description="System uptime in seconds")
    timestamp: datetime = Field(default_factory=datetime.now, description="Health check timestamp")
    components: Dict[str, ComponentHealth] = Field(..., description="Individual component health")
    performance: SystemPerformance = Field(..., description="Performance metrics")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "status": "healthy",
                "version": "1.0.0",
                "uptime_seconds": 86400,
                "timestamp": "2024-11-08T15:30:00Z",
                "components": {
                    "vector_db": "healthy",
                    "embedding_model": "healthy",
                    "cache": "healthy",
                    "explanation_service": "healthy",
                },
                "performance": {
                    "avg_response_time_ms": 1200,
                    "total_queries": 1500,
                    "cache_hit_rate": 0.65,
                    "active_async_jobs": 3,
                },
            }
        }
    )


class SystemStats(BaseModel):
    """System statistics and metrics."""

    total_emails: int = Field(..., description="Total emails in dataset")
    index_size_mb: float = Field(..., description="Search index size in MB")
    cache_size_mb: float = Field(..., description="Cache size in MB")
    memory_usage_mb: float = Field(..., description="Current memory usage in MB")


class QueryStats(BaseModel):
    """Query processing statistics."""

    total: int = Field(..., description="Total queries processed")
    last_24h: int = Field(..., description="Queries in last 24 hours")
    last_1h: int = Field(default=0, description="Queries in last hour")
    avg_response_time_ms: float = Field(..., description="Average response time")
    cache_hit_rate: float = Field(..., description="Cache hit rate")
    most_common_queries: List[str] = Field(
        default_factory=list, description="Most frequent queries"
    )


class ThreatStats(BaseModel):
    """Threat detection statistics."""

    high_risk_detected: int = Field(..., description="High-risk threats detected")
    medium_risk_detected: int = Field(..., description="Medium-risk threats detected")
    low_risk_detected: int = Field(default=0, description="Low-risk threats detected")
    false_positive_rate: float = Field(..., description="Estimated false positive rate")
    most_common_threats: List[str] = Field(
        default_factory=list, description="Most common threat types"
    )


class StatsResponse(BaseModel):
    """Comprehensive system statistics response."""

    timestamp: datetime = Field(default_factory=datetime.now, description="Statistics timestamp")
    system: SystemStats = Field(..., description="System resource statistics")
    queries: QueryStats = Field(..., description="Query processing statistics")
    threats: ThreatStats = Field(..., description="Threat detection statistics")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "timestamp": "2024-11-08T15:30:00Z",
                "system": {
                    "total_emails": 150,
                    "index_size_mb": 45.2,
                    "cache_size_mb": 12.8,
                    "memory_usage_mb": 256,
                },
                "queries": {
                    "total": 1500,
                    "last_24h": 120,
                    "avg_response_time_ms": 1200,
                    "cache_hit_rate": 0.65,
                },
                "threats": {
                    "high_risk_detected": 45,
                    "medium_risk_detected": 78,
                    "false_positive_rate": 0.05,
                },
            }
        }
    )
