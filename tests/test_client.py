"""Tests for SafeNest client."""

import pytest
from safenest import (
    SafeNest,
    Severity,
    GroomingRisk,
    RiskLevel,
    EmotionTrend,
    Audience,
    MessageRole,
    AnalysisContext,
    DetectBullyingInput,
    DetectGroomingInput,
    GroomingMessage,
)


class TestClientInitialization:
    """Tests for client initialization."""

    def test_client_creation(self) -> None:
        """Test basic client creation."""
        client = SafeNest(api_key="test-api-key-12345")
        assert client is not None

    def test_client_with_options(self) -> None:
        """Test client creation with options."""
        client = SafeNest(
            api_key="test-api-key-12345",
            timeout=60.0,
            max_retries=5,
            retry_delay=2.0,
        )
        assert client is not None

    def test_client_requires_api_key(self) -> None:
        """Test that client requires API key."""
        with pytest.raises(ValueError, match="API key is required"):
            SafeNest(api_key="")

    def test_client_validates_api_key_length(self) -> None:
        """Test that client validates API key length."""
        with pytest.raises(ValueError, match="appears to be invalid"):
            SafeNest(api_key="short")


class TestEnums:
    """Tests for enum values."""

    def test_severity_values(self) -> None:
        """Test Severity enum values."""
        assert Severity.LOW.value == "low"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.HIGH.value == "high"
        assert Severity.CRITICAL.value == "critical"

    def test_grooming_risk_values(self) -> None:
        """Test GroomingRisk enum values."""
        assert GroomingRisk.NONE.value == "none"
        assert GroomingRisk.LOW.value == "low"
        assert GroomingRisk.HIGH.value == "high"
        assert GroomingRisk.CRITICAL.value == "critical"

    def test_risk_level_values(self) -> None:
        """Test RiskLevel enum values."""
        assert RiskLevel.SAFE.value == "safe"
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.CRITICAL.value == "critical"

    def test_emotion_trend_values(self) -> None:
        """Test EmotionTrend enum values."""
        assert EmotionTrend.IMPROVING.value == "improving"
        assert EmotionTrend.STABLE.value == "stable"
        assert EmotionTrend.WORSENING.value == "worsening"

    def test_audience_values(self) -> None:
        """Test Audience enum values."""
        assert Audience.CHILD.value == "child"
        assert Audience.PARENT.value == "parent"
        assert Audience.EDUCATOR.value == "educator"
        assert Audience.PLATFORM.value == "platform"

    def test_message_role_values(self) -> None:
        """Test MessageRole enum values."""
        assert MessageRole.ADULT.value == "adult"
        assert MessageRole.CHILD.value == "child"
        assert MessageRole.UNKNOWN.value == "unknown"


class TestModels:
    """Tests for data models."""

    def test_analysis_context(self) -> None:
        """Test AnalysisContext creation."""
        context = AnalysisContext(
            language="en",
            age_group="11-13",
            relationship="classmates",
            platform="chat",
        )
        assert context.language == "en"
        assert context.age_group == "11-13"

    def test_analysis_context_to_dict(self) -> None:
        """Test AnalysisContext.to_dict() excludes None values."""
        context = AnalysisContext(language="en")
        d = context.to_dict()
        assert d == {"language": "en"}
        assert "age_group" not in d

    def test_detect_bullying_input(self) -> None:
        """Test DetectBullyingInput creation."""
        input_data = DetectBullyingInput(
            content="Test message",
            external_id="msg_123",
            metadata={"user_id": "user_456"},
        )
        assert input_data.content == "Test message"
        assert input_data.external_id == "msg_123"

    def test_grooming_message(self) -> None:
        """Test GroomingMessage creation."""
        msg = GroomingMessage(
            role=MessageRole.ADULT,
            content="Hello",
        )
        assert msg.role == MessageRole.ADULT
        assert msg.content == "Hello"

    def test_detect_grooming_input(self) -> None:
        """Test DetectGroomingInput creation."""
        input_data = DetectGroomingInput(
            messages=[
                GroomingMessage(role=MessageRole.ADULT, content="Hello"),
                GroomingMessage(role=MessageRole.CHILD, content="Hi"),
            ],
            child_age=12,
        )
        assert len(input_data.messages) == 2
        assert input_data.child_age == 12
