"""
Search domain models.

Contains search results and queries, independent of search implementation details.
"""

import logging
from typing import List, Optional
from shared.pydantic_compat import BaseModel, Field, model_validator
try:
    from pydantic import ConfigDict  # type: ignore
except ImportError:
    class ConfigDict(dict):  # type: ignore
        pass
import sys
import os

# Add src to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from shared.enums import ThreatLevel, SearchMethod
from shared.constants import THREAT_LEVEL_THRESHOLDS
from data_preparation.schemas.email import Email
from threat_analysis.models.threat import ThreatFeatures

logger = logging.getLogger(__name__)


class SearchQuery(BaseModel):
    """Domain representation of a search query."""
    
    text: str = Field(..., min_length=1, max_length=500, description="Search query text")
    method: SearchMethod = Field(default=SearchMethod.HYBRID, description="Search method to use")
    limit: int = Field(default=10, ge=1, le=100, description="Maximum results to return")
    threat_threshold: Optional[float] = Field(None, ge=0.0, le=1.0, description="Minimum threat score")
    explanation_mode: str = Field(default="text", description="Explanation mode: 'text' or 'json'")
    detail_level: str = Field(default="detailed", description="Explanation detail level: 'compact' or 'detailed'")
    
    def __str__(self) -> str:
        return self.text


class QueryResult(BaseModel):
    """Search result with email, scoring, and explanation."""
    
    email: Email = Field(..., description="The matching email")
    rank: int = Field(..., ge=1, description="Result ranking (1-based)")
    
    # Scoring information
    threat_score: float = Field(..., ge=0.0, le=1.0, description="Overall threat score")
    threat_level: ThreatLevel = Field(..., description="Categorical threat level")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Score confidence")
    
    # Search relevance
    search_score: float = Field(..., ge=0.0, le=1.0, description="Search relevance score")
    keyword_matches: List[str] = Field(default_factory=list, description="Matched keywords")
    semantic_similarity: Optional[float] = Field(None, ge=0.0, le=1.0,
                                                description="Semantic similarity score")
    
    # Threat analysis
    features: ThreatFeatures = Field(..., description="Extracted threat features")
    explanation: str = Field(..., description="Human-readable threat explanation")
    explanation_structured: Optional[dict] = Field(None, description="Structured explanation object when explanation_mode='json'")
    
    # Processing metadata
    processing_time_ms: Optional[int] = Field(None, ge=0, description="Processing time in milliseconds")
    
    @model_validator(mode='after')
    def set_threat_level(self):  # type: ignore[override]
        """Determine threat level from threat_score after model creation."""
        score = getattr(self, 'threat_score', None)
        if score is not None:
            if score >= THREAT_LEVEL_THRESHOLDS['CRITICAL']:
                self.threat_level = ThreatLevel.CRITICAL
            elif score >= THREAT_LEVEL_THRESHOLDS['HIGH']:
                self.threat_level = ThreatLevel.HIGH
            elif score >= THREAT_LEVEL_THRESHOLDS['MEDIUM']:
                self.threat_level = ThreatLevel.MEDIUM
            elif score >= THREAT_LEVEL_THRESHOLDS['LOW']:
                self.threat_level = ThreatLevel.LOW
            else:
                self.threat_level = ThreatLevel.NEGLIGIBLE
        return self
    
    def is_high_risk(self) -> bool:
        """Check if this result represents a high-risk threat."""
        return self.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]
    
    model_config = ConfigDict(json_schema_extra={
            "example": {
                "rank": 1,
                "threat_score": 0.92,
                "threat_level": "HIGH",
                "confidence": 0.89,
                "search_score": 0.87,
                "keyword_matches": ["urgent", "payment", "suspended"],
                "semantic_similarity": 0.85,
                "explanation": "High-risk phishing: urgent language (0.9) + executable attachment (0.95)"
            }
        })


class SearchResults(BaseModel):
    """Container for search results with metadata."""
    
    query: SearchQuery = Field(..., description="Original search query")
    results: List[QueryResult] = Field(..., description="Ranked search results")
    total_found: int = Field(..., ge=0, description="Total results found")
    processing_time_ms: int = Field(..., ge=0, description="Total processing time")
    
    def get_high_risk_results(self) -> List[QueryResult]:
        """Get only high-risk results."""
        return [result for result in self.results if result.is_high_risk()]
    
    def get_results_above_threshold(self, threshold: float) -> List[QueryResult]:
        """Get results above a specific threat score threshold."""
        return [result for result in self.results if result.threat_score >= threshold]
