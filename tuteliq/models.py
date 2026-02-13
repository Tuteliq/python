"""Data models for Tuteliq SDK."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


# =============================================================================
# Enums
# =============================================================================


class Severity(str, Enum):
    """Severity levels for detected content."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class GroomingRisk(str, Enum):
    """Grooming risk levels."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskLevel(str, Enum):
    """Overall risk levels."""

    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EmotionTrend(str, Enum):
    """Emotion trend direction."""

    IMPROVING = "improving"
    STABLE = "stable"
    WORSENING = "worsening"


class Audience(str, Enum):
    """Target audience for action plans."""

    CHILD = "child"
    PARENT = "parent"
    EDUCATOR = "educator"
    PLATFORM = "platform"


class MessageRole(str, Enum):
    """Message role in conversations."""

    ADULT = "adult"
    CHILD = "child"
    UNKNOWN = "unknown"


# =============================================================================
# Common Types
# =============================================================================


@dataclass
class AnalysisContext:
    """Context for content analysis."""

    language: Optional[str] = None
    age_group: Optional[str] = None
    relationship: Optional[str] = None
    platform: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary, excluding None values."""
        return {k: v for k, v in {
            "language": self.language,
            "age_group": self.age_group,
            "relationship": self.relationship,
            "platform": self.platform,
        }.items() if v is not None}


@dataclass
class Usage:
    """API usage statistics."""

    limit: int
    used: int
    remaining: int


# =============================================================================
# Bullying Detection
# =============================================================================


@dataclass
class DetectBullyingInput:
    """Input for bullying detection."""

    content: str
    context: Optional[AnalysisContext] = None
    external_id: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None


@dataclass
class BullyingResult:
    """Result from bullying detection."""

    is_bullying: bool
    bullying_type: list[str]
    confidence: float
    severity: Severity
    rationale: str
    recommended_action: str
    risk_score: float
    external_id: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BullyingResult":
        """Create from API response dictionary."""
        return cls(
            is_bullying=data["is_bullying"],
            bullying_type=data["bullying_type"],
            confidence=data["confidence"],
            severity=Severity(data["severity"]),
            rationale=data["rationale"],
            recommended_action=data["recommended_action"],
            risk_score=data["risk_score"],
            external_id=data.get("external_id"),
            metadata=data.get("metadata"),
        )


# =============================================================================
# Grooming Detection
# =============================================================================


@dataclass
class GroomingMessage:
    """A message in a conversation for grooming detection."""

    role: MessageRole
    content: str
    timestamp: Optional[str] = None


@dataclass
class DetectGroomingInput:
    """Input for grooming detection."""

    messages: list[GroomingMessage]
    child_age: Optional[int] = None
    context: Optional[AnalysisContext] = None
    external_id: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None


@dataclass
class GroomingResult:
    """Result from grooming detection."""

    grooming_risk: GroomingRisk
    confidence: float
    flags: list[str]
    rationale: str
    risk_score: float
    recommended_action: str
    external_id: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "GroomingResult":
        """Create from API response dictionary."""
        return cls(
            grooming_risk=GroomingRisk(data["grooming_risk"]),
            confidence=data["confidence"],
            flags=data["flags"],
            rationale=data["rationale"],
            risk_score=data["risk_score"],
            recommended_action=data["recommended_action"],
            external_id=data.get("external_id"),
            metadata=data.get("metadata"),
        )


# =============================================================================
# Unsafe Content Detection
# =============================================================================


@dataclass
class DetectUnsafeInput:
    """Input for unsafe content detection."""

    content: str
    context: Optional[AnalysisContext] = None
    external_id: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None


@dataclass
class UnsafeResult:
    """Result from unsafe content detection."""

    unsafe: bool
    categories: list[str]
    severity: Severity
    confidence: float
    risk_score: float
    rationale: str
    recommended_action: str
    external_id: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "UnsafeResult":
        """Create from API response dictionary."""
        return cls(
            unsafe=data["unsafe"],
            categories=data["categories"],
            severity=Severity(data["severity"]),
            confidence=data["confidence"],
            risk_score=data["risk_score"],
            rationale=data["rationale"],
            recommended_action=data["recommended_action"],
            external_id=data.get("external_id"),
            metadata=data.get("metadata"),
        )


# =============================================================================
# Quick Analysis
# =============================================================================


@dataclass
class AnalyzeInput:
    """Input for quick analysis."""

    content: str
    context: Optional[AnalysisContext] = None
    include: Optional[list[str]] = None  # ["bullying", "unsafe"]
    external_id: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None


@dataclass
class AnalyzeResult:
    """Result from quick analysis."""

    risk_level: RiskLevel
    risk_score: float
    summary: str
    bullying: Optional[BullyingResult] = None
    unsafe: Optional[UnsafeResult] = None
    recommended_action: str = "none"
    external_id: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None


# =============================================================================
# Emotion Analysis
# =============================================================================


@dataclass
class EmotionMessage:
    """A message for emotion analysis."""

    sender: str
    content: str
    timestamp: Optional[str] = None


@dataclass
class AnalyzeEmotionsInput:
    """Input for emotion analysis."""

    content: Optional[str] = None
    messages: Optional[list[EmotionMessage]] = None
    context: Optional[AnalysisContext] = None
    external_id: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None


@dataclass
class EmotionsResult:
    """Result from emotion analysis."""

    dominant_emotions: list[str]
    emotion_scores: dict[str, float]
    trend: EmotionTrend
    summary: str
    recommended_followup: str
    external_id: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EmotionsResult":
        """Create from API response dictionary."""
        return cls(
            dominant_emotions=data["dominant_emotions"],
            emotion_scores=data["emotion_scores"],
            trend=EmotionTrend(data["trend"]),
            summary=data["summary"],
            recommended_followup=data["recommended_followup"],
            external_id=data.get("external_id"),
            metadata=data.get("metadata"),
        )


# =============================================================================
# Action Plan
# =============================================================================


@dataclass
class GetActionPlanInput:
    """Input for action plan generation."""

    situation: str
    child_age: Optional[int] = None
    audience: Optional[Audience] = None
    severity: Optional[Severity] = None
    external_id: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None


@dataclass
class ActionPlanResult:
    """Result from action plan generation."""

    audience: str
    steps: list[str]
    tone: str
    reading_level: Optional[str] = None
    external_id: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ActionPlanResult":
        """Create from API response dictionary."""
        return cls(
            audience=data["audience"],
            steps=data["steps"],
            tone=data["tone"],
            reading_level=data.get("approx_reading_level"),
            external_id=data.get("external_id"),
            metadata=data.get("metadata"),
        )


# =============================================================================
# Incident Report
# =============================================================================


@dataclass
class ReportMessage:
    """A message for incident report."""

    sender: str
    content: str
    timestamp: Optional[str] = None


@dataclass
class GenerateReportInput:
    """Input for incident report generation."""

    messages: list[ReportMessage]
    child_age: Optional[int] = None
    incident_type: Optional[str] = None
    occurred_at: Optional[str] = None
    notes: Optional[str] = None
    external_id: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None


@dataclass
class ReportResult:
    """Result from incident report generation."""

    summary: str
    risk_level: RiskLevel
    categories: list[str]
    recommended_next_steps: list[str]
    external_id: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ReportResult":
        """Create from API response dictionary."""
        return cls(
            summary=data["summary"],
            risk_level=RiskLevel(data["risk_level"]),
            categories=data["categories"],
            recommended_next_steps=data["recommended_next_steps"],
            external_id=data.get("external_id"),
            metadata=data.get("metadata"),
        )


# =============================================================================
# Account Management (GDPR)
# =============================================================================


@dataclass
class AccountDeletionResult:
    """Result from account data deletion (GDPR Article 17)."""

    message: str
    deleted_count: int

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AccountDeletionResult":
        """Create from API response dictionary."""
        return cls(
            message=data["message"],
            deleted_count=data["deleted_count"],
        )


@dataclass
class AccountExportResult:
    """Result from account data export (GDPR Article 20)."""

    user_id: str
    exported_at: str
    data: dict[str, Any]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AccountExportResult":
        """Create from API response dictionary."""
        return cls(
            user_id=data["userId"],
            exported_at=data["exportedAt"],
            data=data["data"],
        )


# =============================================================================
# Consent Management (GDPR Article 7)
# =============================================================================


class ConsentType(str, Enum):
    """Types of consent that can be recorded."""

    DATA_PROCESSING = "data_processing"
    ANALYTICS = "analytics"
    MARKETING = "marketing"
    THIRD_PARTY_SHARING = "third_party_sharing"
    CHILD_SAFETY_MONITORING = "child_safety_monitoring"


class ConsentStatus(str, Enum):
    """Consent status."""

    GRANTED = "granted"
    WITHDRAWN = "withdrawn"


@dataclass
class RecordConsentInput:
    """Input for recording consent."""

    consent_type: ConsentType
    version: str


@dataclass
class ConsentRecord:
    """A consent record."""

    id: str
    user_id: str
    consent_type: ConsentType
    status: ConsentStatus
    version: str
    created_at: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ConsentRecord":
        """Create from API response dictionary."""
        return cls(
            id=data["id"],
            user_id=data["user_id"],
            consent_type=ConsentType(data["consent_type"]),
            status=ConsentStatus(data["status"]),
            version=data["version"],
            created_at=data["created_at"],
        )


@dataclass
class ConsentActionResult:
    """Result from consent record/withdraw operations."""

    message: str
    consent: ConsentRecord

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ConsentActionResult":
        """Create from API response dictionary."""
        return cls(
            message=data["message"],
            consent=ConsentRecord.from_dict(data["consent"]),
        )


@dataclass
class ConsentStatusResult:
    """Result from consent status query."""

    consents: list[ConsentRecord]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ConsentStatusResult":
        """Create from API response dictionary."""
        return cls(
            consents=[ConsentRecord.from_dict(c) for c in data["consents"]],
        )


# =============================================================================
# Right to Rectification (GDPR Article 16)
# =============================================================================


@dataclass
class RectifyDataInput:
    """Input for data rectification."""

    collection: str
    document_id: str
    fields: dict[str, Any]


@dataclass
class RectifyDataResult:
    """Result from data rectification."""

    message: str
    updated_fields: list[str]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RectifyDataResult":
        """Create from API response dictionary."""
        return cls(
            message=data["message"],
            updated_fields=data["updated_fields"],
        )


# =============================================================================
# Audit Logs (GDPR Article 15)
# =============================================================================


class AuditAction(str, Enum):
    """Types of auditable actions."""

    DATA_ACCESS = "data_access"
    DATA_EXPORT = "data_export"
    DATA_DELETION = "data_deletion"
    DATA_RECTIFICATION = "data_rectification"
    CONSENT_GRANTED = "consent_granted"
    CONSENT_WITHDRAWN = "consent_withdrawn"
    BREACH_NOTIFICATION = "breach_notification"


@dataclass
class AuditLogEntry:
    """An audit log entry."""

    id: str
    user_id: str
    action: AuditAction
    created_at: str
    details: Optional[dict[str, Any]] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuditLogEntry":
        """Create from API response dictionary."""
        return cls(
            id=data["id"],
            user_id=data["user_id"],
            action=AuditAction(data["action"]),
            created_at=data["created_at"],
            details=data.get("details"),
        )


@dataclass
class AuditLogsResult:
    """Result from audit logs query."""

    audit_logs: list[AuditLogEntry]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuditLogsResult":
        """Create from API response dictionary."""
        return cls(
            audit_logs=[AuditLogEntry.from_dict(l) for l in data["audit_logs"]],
        )


# =============================================================================
# Breach Management (GDPR Article 33/34)
# =============================================================================


class BreachSeverity(str, Enum):
    """Breach severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class BreachStatus(str, Enum):
    """Breach status values."""

    DETECTED = "detected"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    REPORTED = "reported"
    RESOLVED = "resolved"


class BreachNotificationStatus(str, Enum):
    """Breach notification status values."""

    PENDING = "pending"
    USERS_NOTIFIED = "users_notified"
    DPA_NOTIFIED = "dpa_notified"
    COMPLETED = "completed"


@dataclass
class LogBreachInput:
    """Input for logging a data breach."""

    title: str
    description: str
    severity: BreachSeverity
    affected_user_ids: list[str]
    data_categories: list[str]
    reported_by: str


@dataclass
class UpdateBreachInput:
    """Input for updating a breach."""

    status: BreachStatus
    notification_status: Optional[BreachNotificationStatus] = None
    notes: Optional[str] = None


@dataclass
class BreachRecord:
    """A breach record."""

    id: str
    title: str
    description: str
    severity: BreachSeverity
    status: BreachStatus
    notification_status: BreachNotificationStatus
    affected_user_ids: list[str]
    data_categories: list[str]
    reported_by: str
    notification_deadline: str
    created_at: str
    updated_at: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BreachRecord":
        """Create from API response dictionary."""
        return cls(
            id=data["id"],
            title=data["title"],
            description=data["description"],
            severity=BreachSeverity(data["severity"]),
            status=BreachStatus(data["status"]),
            notification_status=BreachNotificationStatus(data["notification_status"]),
            affected_user_ids=data["affected_user_ids"],
            data_categories=data["data_categories"],
            reported_by=data["reported_by"],
            notification_deadline=data["notification_deadline"],
            created_at=data["created_at"],
            updated_at=data["updated_at"],
        )


@dataclass
class LogBreachResult:
    """Result from logging a breach."""

    message: str
    breach: BreachRecord

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LogBreachResult":
        """Create from API response dictionary."""
        return cls(
            message=data["message"],
            breach=BreachRecord.from_dict(data["breach"]),
        )


@dataclass
class BreachListResult:
    """Result from listing breaches."""

    breaches: list[BreachRecord]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BreachListResult":
        """Create from API response dictionary."""
        return cls(
            breaches=[BreachRecord.from_dict(b) for b in data["breaches"]],
        )


@dataclass
class BreachResult:
    """Result from getting/updating a breach."""

    breach: BreachRecord

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BreachResult":
        """Create from API response dictionary."""
        return cls(
            breach=BreachRecord.from_dict(data["breach"]),
        )
