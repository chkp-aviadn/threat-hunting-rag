"""
Threat analysis domain models.

Contains threat features and analysis results for phishing detection,
independent of infrastructure or API concerns.
"""

import logging
from datetime import datetime
from typing import Dict, Tuple
from pydantic import BaseModel, Field
try:
    from pydantic import ConfigDict  # type: ignore
except ImportError:
    class ConfigDict(dict):  # type: ignore
        pass
import sys
import os

# Add src to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from shared.enums import ThreatLevel
from shared.constants import AGGREGATED_FEATURE_WEIGHTS

logger = logging.getLogger(__name__)


class ThreatFeatures(BaseModel):
    """Threat indicators extracted from email content."""
    
    # Language-based features
    urgent_language: float = Field(default=0.0, ge=0.0, le=1.0, 
                                 description="Urgency language detection score")
    suspicious_language: float = Field(default=0.0, ge=0.0, le=1.0,
                                     description="Suspicious phrasing score") 
    
    # Sender-based features  
    executive_impersonation: float = Field(default=0.0, ge=0.0, le=1.0,
                                         description="Executive impersonation score")
    new_sender: float = Field(default=0.0, ge=0.0, le=1.0,
                            description="Unknown/new sender score")
    domain_suspicious: float = Field(default=0.0, ge=0.0, le=1.0,
                                   description="Suspicious domain score")
    
    # Attachment-based features
    suspicious_attachment: float = Field(default=0.0, ge=0.0, le=1.0,
                                       description="Suspicious attachment score")
    executable_attachment: float = Field(default=0.0, ge=0.0, le=1.0,
                                       description="Executable attachment score")
    
    # Content-based features
    financial_request: float = Field(default=0.0, ge=0.0, le=1.0,
                                   description="Financial request score")
    credential_harvest: float = Field(default=0.0, ge=0.0, le=1.0,
                                    description="Credential harvesting score")
    link_suspicious: float = Field(default=0.0, ge=0.0, le=1.0,
                                 description="Suspicious link score")
    
    # Temporal features
    outside_hours: float = Field(default=0.0, ge=0.0, le=1.0,
                               description="Outside business hours score")
    
    # Feature metadata
    extraction_timestamp: datetime = Field(default_factory=datetime.utcnow,
                                         description="Feature extraction time")
    overall_risk_score: float = Field(default=0.0, ge=0.0, le=1.0,
                                     description="Overall aggregated risk score")
    
    def get_top_features(self, threshold: float = 0.1) -> Dict[str, float]:
        """Get features above threshold, sorted by score."""
        features = {}
        # Use dict() for compatibility with different Pydantic versions
        # Prefer Pydantic v2 model_dump(), fallback gracefully for legacy compatibility
        if hasattr(self, 'model_dump'):
            model_dict = self.model_dump()
        elif hasattr(self, 'dict'):
            model_dict = self.dict()
        else:
            model_dict = self.__dict__
        for field_name, field_value in model_dict.items():
            if field_name != 'extraction_timestamp' and isinstance(field_value, (int, float)):
                if field_value >= threshold:
                    features[field_name] = field_value
        
        return dict(sorted(features.items(), key=lambda x: x[1], reverse=True))
    
    def get_max_feature(self) -> Tuple[str, float]:
        """Get the highest scoring feature."""
        features = self.get_top_features(threshold=0.0)
        if features:
            return max(features.items(), key=lambda x: x[1])
        return ("none", 0.0)
    
    def get_overall_score(self) -> float:
        """Calculate overall threat score using weighted features (centralized constants)."""
        total_score = 0.0
        total_weight = 0.0
        for feature, weight in AGGREGATED_FEATURE_WEIGHTS.items():
            if hasattr(self, feature):
                val = getattr(self, feature)
                if val > 0:
                    total_score += val * weight
                    total_weight += weight
        return total_score / total_weight if total_weight > 0 else 0.0
    
    model_config = ConfigDict(
        json_encoders={
            datetime: lambda v: v.isoformat()
        },
        json_schema_extra={
            "example": {
                "urgent_language": 0.9,
                "suspicious_attachment": 0.8,
                "executive_impersonation": 0.7,
                "new_sender": 0.6,
                "financial_request": 0.85
            }
        }
    )
