"""
Email domain model - core business entity.

Pure domain model representing an email with validation and business logic,
independent of infrastructure concerns.
"""

import logging
from datetime import datetime
from typing import List, Optional
from shared.pydantic_compat import BaseModel, Field, model_validator

try:
    from pydantic import ConfigDict  # type: ignore
except ImportError:

    class ConfigDict(dict):  # type: ignore
        pass


from pydantic import EmailStr
import uuid
import sys
import os

# Add src to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from shared.enums import ThreatLevel

logger = logging.getLogger(__name__)


class EmailAttachment(BaseModel):
    """Email attachment model."""

    filename: str = Field(..., description="Name of the attachment file")
    size: int = Field(..., ge=0, description="Size of the attachment in bytes")
    content_type: Optional[str] = Field(None, description="MIME content type")

    def get_extension(self) -> str:
        """Get file extension in lowercase."""
        return self.filename.split(".")[-1].lower() if "." in self.filename else ""

    def is_suspicious(self) -> bool:
        """Check if attachment has suspicious extension."""
        suspicious_extensions = {".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".js", ".jar"}
        return f".{self.get_extension()}" in suspicious_extensions


class Email(BaseModel):
    """Email domain entity with validation and business logic."""

    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()), description="Unique email identifier"
    )
    sender: EmailStr = Field(..., description="Sender email address")
    sender_domain: Optional[str] = Field(None, description="Sender domain extracted from email")
    recipient: Optional[EmailStr] = Field(None, description="Recipient email address")
    subject: str = Field(..., min_length=1, max_length=500, description="Email subject line")
    body: str = Field(..., min_length=1, description="Email body content")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Email timestamp")

    # Attachments
    attachments: List[EmailAttachment] = Field(
        default_factory=list, description="List of email attachments"
    )
    attachment_count: int = Field(default=0, description="Number of attachments")

    # Domain metadata
    is_phishing: bool = Field(default=False, description="Ground truth phishing label")
    phishing_type: Optional[str] = Field(None, description="Type of phishing attack")
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0, description="Labeling confidence")

    # Processing metadata
    created_at: datetime = Field(
        default_factory=datetime.utcnow, description="Record creation time"
    )

    @model_validator(mode="after")
    def populate_derived_fields(self):  # type: ignore[override]
        """Populate derived fields (attachment_count, sender_domain) after initialization.

        This replaces multiple legacy @validator usages with a single Pydantic v2 style
        model validator for cross-field consistency.
        """
        # Ensure attachment_count matches actual list length
        actual_count = len(self.attachments)
        if self.attachment_count not in (0, actual_count):
            logger.warning(
                f"Attachment count mismatch: provided={self.attachment_count}, actual={actual_count}"
            )
        self.attachment_count = actual_count

        # Derive sender_domain if missing
        if not self.sender_domain and self.sender and "@" in str(self.sender):
            self.sender_domain = str(self.sender).split("@")[1]
            logger.debug(f"Extracted domain '{self.sender_domain}' from sender '{self.sender}'")
        return self

    def get_content(self) -> str:
        """Get combined content for analysis."""
        return f"{self.subject} {self.body}"

    def has_suspicious_attachments(self) -> bool:
        """Check if email has potentially suspicious attachments."""
        return any(attachment.is_suspicious() for attachment in self.attachments)

    model_config = ConfigDict(
        json_encoders={datetime: lambda v: v.isoformat()},
        json_schema_extra={
            "example": {
                "id": "email_123",
                "sender": "finance@company.com",
                "sender_domain": "company.com",
                "recipient": "user@company.com",
                "subject": "Urgent: Payment Required",
                "body": "Dear Customer, Your account requires immediate payment...",
                "attachments": [{"filename": "invoice.pdf", "size": 1024}],
                "attachment_count": 1,
                "is_phishing": True,
                "phishing_type": "urgent_payment",
                "confidence": 0.95,
            }
        },
    )
