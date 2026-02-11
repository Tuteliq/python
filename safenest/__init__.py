"""
SafeNest - AI-powered child safety API

Official Python SDK for detecting bullying, grooming, and unsafe content.

Example:
    >>> from safenest import SafeNest
    >>> client = SafeNest(api_key="your-api-key")
    >>> result = await client.detect_bullying("Some text to analyze")
    >>> print(result.is_bullying)
"""

from safenest.client import SafeNest
from safenest.models import (
    # Enums
    Severity,
    GroomingRisk,
    RiskLevel,
    EmotionTrend,
    Audience,
    MessageRole,
    # Input types
    AnalysisContext,
    DetectBullyingInput,
    DetectGroomingInput,
    DetectUnsafeInput,
    AnalyzeInput,
    AnalyzeEmotionsInput,
    GetActionPlanInput,
    GenerateReportInput,
    GroomingMessage,
    EmotionMessage,
    ReportMessage,
    # Result types
    BullyingResult,
    GroomingResult,
    UnsafeResult,
    AnalyzeResult,
    EmotionsResult,
    ActionPlanResult,
    ReportResult,
    Usage,
    # Account types (GDPR)
    AccountDeletionResult,
    AccountExportResult,
)
from safenest.errors import (
    SafeNestError,
    AuthenticationError,
    RateLimitError,
    ValidationError,
    NotFoundError,
    ServerError,
    TimeoutError,
    NetworkError,
)

__version__ = "1.1.0"
__all__ = [
    # Client
    "SafeNest",
    # Enums
    "Severity",
    "GroomingRisk",
    "RiskLevel",
    "EmotionTrend",
    "Audience",
    "MessageRole",
    # Input types
    "AnalysisContext",
    "DetectBullyingInput",
    "DetectGroomingInput",
    "DetectUnsafeInput",
    "AnalyzeInput",
    "AnalyzeEmotionsInput",
    "GetActionPlanInput",
    "GenerateReportInput",
    "GroomingMessage",
    "EmotionMessage",
    "ReportMessage",
    # Result types
    "BullyingResult",
    "GroomingResult",
    "UnsafeResult",
    "AnalyzeResult",
    "EmotionsResult",
    "ActionPlanResult",
    "ReportResult",
    "Usage",
    # Account types (GDPR)
    "AccountDeletionResult",
    "AccountExportResult",
    # Errors
    "SafeNestError",
    "AuthenticationError",
    "RateLimitError",
    "ValidationError",
    "NotFoundError",
    "ServerError",
    "TimeoutError",
    "NetworkError",
]
