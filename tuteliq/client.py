"""Tuteliq API client."""

import asyncio
from typing import Any, Optional, Union

import httpx

from tuteliq.errors import (
    AuthenticationError,
    NetworkError,
    NotFoundError,
    RateLimitError,
    TuteliqError,
    ServerError,
    TimeoutError,
    ValidationError,
)
from tuteliq.models import (
    AccountDeletionResult,
    AccountExportResult,
    ActionPlanResult,
    AnalysisContext,
    AnalyzeEmotionsInput,
    AnalyzeInput,
    AnalyzeResult,
    AuditAction,
    AuditLogsResult,
    Audience,
    BreachNotificationStatus,
    BreachResult,
    BreachListResult,
    BreachSeverity,
    BreachStatus,
    BullyingResult,
    ConsentActionResult,
    ConsentStatusResult,
    ConsentType,
    DetectBullyingInput,
    DetectGroomingInput,
    DetectUnsafeInput,
    EmotionMessage,
    EmotionsResult,
    GenerateReportInput,
    GetActionPlanInput,
    GroomingResult,
    LogBreachInput,
    LogBreachResult,
    RecordConsentInput,
    RectifyDataInput,
    RectifyDataResult,
    RiskLevel,
    UnsafeResult,
    UpdateBreachInput,
    ReportResult,
    Usage,
)


class Tuteliq:
    """Tuteliq API client for child safety analysis.

    Example:
        >>> client = Tuteliq(api_key="your-api-key")
        >>> result = await client.detect_bullying("Some text to analyze")
        >>> if result.is_bullying:
        ...     print(f"Severity: {result.severity}")

    Attributes:
        usage: Current usage statistics (updated after each request).
        last_request_id: Request ID from the last API call.
        last_latency_ms: Latency of the last request in milliseconds.
    """

    BASE_URL = "https://api.tuteliq.ai"

    def __init__(
        self,
        api_key: str,
        *,
        timeout: float = 30.0,
        max_retries: int = 3,
        retry_delay: float = 1.0,
    ) -> None:
        """Initialize Tuteliq client.

        Args:
            api_key: Your Tuteliq API key.
            timeout: Request timeout in seconds (default: 30).
            max_retries: Number of retry attempts for transient failures (default: 3).
            retry_delay: Initial retry delay in seconds (default: 1).
        """
        if not api_key:
            raise ValueError("API key is required")
        if len(api_key) < 10:
            raise ValueError("API key appears to be invalid")

        self._api_key = api_key
        self._timeout = timeout
        self._max_retries = max_retries
        self._retry_delay = retry_delay

        self._client = httpx.AsyncClient(
            base_url=self.BASE_URL,
            timeout=timeout,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
        )

        # Usage tracking
        self.usage: Optional[Usage] = None
        self.last_request_id: Optional[str] = None
        self.last_latency_ms: Optional[float] = None

    async def __aenter__(self) -> "Tuteliq":
        """Async context manager entry."""
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Async context manager exit."""
        await self.close()

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

    # =========================================================================
    # Safety Detection
    # =========================================================================

    async def detect_bullying(
        self,
        content_or_input: Union[str, DetectBullyingInput],
        *,
        context: Optional[AnalysisContext] = None,
        external_id: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> BullyingResult:
        """Detect bullying in content.

        Args:
            content_or_input: Text content or DetectBullyingInput object.
            context: Analysis context (if using string input).
            external_id: Your identifier for correlation.
            metadata: Custom metadata.

        Returns:
            BullyingResult with detection details.
        """
        if isinstance(content_or_input, str):
            input_data = DetectBullyingInput(
                content=content_or_input,
                context=context,
                external_id=external_id,
                metadata=metadata,
            )
        else:
            input_data = content_or_input

        body: dict[str, Any] = {"text": input_data.content}
        if input_data.context:
            body["context"] = input_data.context.to_dict()
        if input_data.external_id:
            body["external_id"] = input_data.external_id
        if input_data.metadata:
            body["metadata"] = input_data.metadata

        data = await self._request("POST", "/api/v1/safety/bullying", body)
        return BullyingResult.from_dict(data)

    async def detect_grooming(
        self, input_data: DetectGroomingInput
    ) -> GroomingResult:
        """Detect grooming patterns in a conversation.

        Args:
            input_data: DetectGroomingInput with messages and context.

        Returns:
            GroomingResult with detection details.
        """
        body: dict[str, Any] = {
            "messages": [
                {"sender_role": msg.role.value, "text": msg.content}
                for msg in input_data.messages
            ]
        }

        context: dict[str, Any] = {}
        if input_data.child_age:
            context["child_age"] = input_data.child_age
        if input_data.context:
            context.update(input_data.context.to_dict())
        if context:
            body["context"] = context

        if input_data.external_id:
            body["external_id"] = input_data.external_id
        if input_data.metadata:
            body["metadata"] = input_data.metadata

        data = await self._request("POST", "/api/v1/safety/grooming", body)
        return GroomingResult.from_dict(data)

    async def detect_unsafe(
        self,
        content_or_input: Union[str, DetectUnsafeInput],
        *,
        context: Optional[AnalysisContext] = None,
        external_id: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> UnsafeResult:
        """Detect unsafe content.

        Args:
            content_or_input: Text content or DetectUnsafeInput object.
            context: Analysis context (if using string input).
            external_id: Your identifier for correlation.
            metadata: Custom metadata.

        Returns:
            UnsafeResult with detection details.
        """
        if isinstance(content_or_input, str):
            input_data = DetectUnsafeInput(
                content=content_or_input,
                context=context,
                external_id=external_id,
                metadata=metadata,
            )
        else:
            input_data = content_or_input

        body: dict[str, Any] = {"text": input_data.content}
        if input_data.context:
            body["context"] = input_data.context.to_dict()
        if input_data.external_id:
            body["external_id"] = input_data.external_id
        if input_data.metadata:
            body["metadata"] = input_data.metadata

        data = await self._request("POST", "/api/v1/safety/unsafe", body)
        return UnsafeResult.from_dict(data)

    async def analyze(
        self,
        content_or_input: Union[str, AnalyzeInput],
        *,
        context: Optional[AnalysisContext] = None,
        include: Optional[list[str]] = None,
        external_id: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> AnalyzeResult:
        """Quick analysis - runs bullying and unsafe detection in parallel.

        Args:
            content_or_input: Text content or AnalyzeInput object.
            context: Analysis context (if using string input).
            include: Which checks to run (default: ["bullying", "unsafe"]).
            external_id: Your identifier for correlation.
            metadata: Custom metadata.

        Returns:
            AnalyzeResult with combined results.
        """
        if isinstance(content_or_input, str):
            input_data = AnalyzeInput(
                content=content_or_input,
                context=context,
                include=include,
                external_id=external_id,
                metadata=metadata,
            )
        else:
            input_data = content_or_input

        checks = input_data.include or ["bullying", "unsafe"]

        # Run detections in parallel
        tasks = []
        check_types = []

        if "bullying" in checks:
            check_types.append("bullying")
            tasks.append(
                self.detect_bullying(
                    input_data.content,
                    context=input_data.context,
                    external_id=input_data.external_id,
                    metadata=input_data.metadata,
                )
            )

        if "unsafe" in checks:
            check_types.append("unsafe")
            tasks.append(
                self.detect_unsafe(
                    input_data.content,
                    context=input_data.context,
                    external_id=input_data.external_id,
                    metadata=input_data.metadata,
                )
            )

        results = await asyncio.gather(*tasks)

        # Process results
        bullying_result: Optional[BullyingResult] = None
        unsafe_result: Optional[UnsafeResult] = None
        max_risk_score = 0.0

        for i, result in enumerate(results):
            if check_types[i] == "bullying":
                bullying_result = result  # type: ignore
                max_risk_score = max(max_risk_score, bullying_result.risk_score)
            elif check_types[i] == "unsafe":
                unsafe_result = result  # type: ignore
                max_risk_score = max(max_risk_score, unsafe_result.risk_score)

        # Determine risk level
        if max_risk_score >= 0.9:
            risk_level = RiskLevel.CRITICAL
        elif max_risk_score >= 0.7:
            risk_level = RiskLevel.HIGH
        elif max_risk_score >= 0.5:
            risk_level = RiskLevel.MEDIUM
        elif max_risk_score >= 0.3:
            risk_level = RiskLevel.LOW
        else:
            risk_level = RiskLevel.SAFE

        # Build summary
        findings = []
        if bullying_result and bullying_result.is_bullying:
            findings.append(f"Bullying detected ({bullying_result.severity.value})")
        if unsafe_result and unsafe_result.unsafe:
            findings.append(f"Unsafe content: {', '.join(unsafe_result.categories)}")
        summary = ". ".join(findings) if findings else "No safety concerns detected."

        # Determine recommended action
        recommended_action = "none"
        actions = []
        if bullying_result:
            actions.append(bullying_result.recommended_action)
        if unsafe_result:
            actions.append(unsafe_result.recommended_action)

        if "immediate_intervention" in actions:
            recommended_action = "immediate_intervention"
        elif "flag_for_moderator" in actions:
            recommended_action = "flag_for_moderator"
        elif "monitor" in actions:
            recommended_action = "monitor"

        return AnalyzeResult(
            risk_level=risk_level,
            risk_score=max_risk_score,
            summary=summary,
            bullying=bullying_result,
            unsafe=unsafe_result,
            recommended_action=recommended_action,
            external_id=input_data.external_id,
            metadata=input_data.metadata,
        )

    # =========================================================================
    # Emotion Analysis
    # =========================================================================

    async def analyze_emotions(
        self,
        content_or_input: Union[str, AnalyzeEmotionsInput],
        *,
        context: Optional[AnalysisContext] = None,
        external_id: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> EmotionsResult:
        """Analyze emotions in content or conversation.

        Args:
            content_or_input: Text content or AnalyzeEmotionsInput object.
            context: Analysis context (if using string input).
            external_id: Your identifier for correlation.
            metadata: Custom metadata.

        Returns:
            EmotionsResult with emotion analysis.
        """
        if isinstance(content_or_input, str):
            input_data = AnalyzeEmotionsInput(
                content=content_or_input,
                context=context,
                external_id=external_id,
                metadata=metadata,
            )
        else:
            input_data = content_or_input

        body: dict[str, Any] = {}

        if input_data.content:
            body["messages"] = [{"sender": "user", "text": input_data.content}]
        elif input_data.messages:
            body["messages"] = [
                {"sender": msg.sender, "text": msg.content}
                for msg in input_data.messages
            ]

        if input_data.context:
            body["context"] = input_data.context.to_dict()
        if input_data.external_id:
            body["external_id"] = input_data.external_id
        if input_data.metadata:
            body["metadata"] = input_data.metadata

        data = await self._request("POST", "/api/v1/analysis/emotions", body)
        return EmotionsResult.from_dict(data)

    # =========================================================================
    # Guidance
    # =========================================================================

    async def get_action_plan(
        self, input_data: GetActionPlanInput
    ) -> ActionPlanResult:
        """Get age-appropriate action guidance.

        Args:
            input_data: GetActionPlanInput with situation details.

        Returns:
            ActionPlanResult with guidance steps.
        """
        body: dict[str, Any] = {
            "role": (input_data.audience or Audience.PARENT).value,
            "situation": input_data.situation,
        }

        if input_data.child_age:
            body["child_age"] = input_data.child_age
        if input_data.severity:
            body["severity"] = input_data.severity.value
        if input_data.external_id:
            body["external_id"] = input_data.external_id
        if input_data.metadata:
            body["metadata"] = input_data.metadata

        data = await self._request("POST", "/api/v1/guidance/action-plan", body)
        return ActionPlanResult.from_dict(data)

    # =========================================================================
    # Reports
    # =========================================================================

    async def generate_report(
        self, input_data: GenerateReportInput
    ) -> ReportResult:
        """Generate an incident report.

        Args:
            input_data: GenerateReportInput with messages and details.

        Returns:
            ReportResult with incident summary.
        """
        body: dict[str, Any] = {
            "messages": [
                {"sender": msg.sender, "text": msg.content}
                for msg in input_data.messages
            ]
        }

        meta: dict[str, Any] = {}
        if input_data.child_age:
            meta["child_age"] = input_data.child_age
        if input_data.incident_type:
            meta["type"] = input_data.incident_type
        if meta:
            body["meta"] = meta

        if input_data.external_id:
            body["external_id"] = input_data.external_id
        if input_data.metadata:
            body["metadata"] = input_data.metadata

        data = await self._request("POST", "/api/v1/reports/incident", body)
        return ReportResult.from_dict(data)

    # =========================================================================
    # Account Management (GDPR)
    # =========================================================================

    async def delete_account_data(self) -> AccountDeletionResult:
        """Delete all account data (GDPR Article 17 — Right to Erasure).

        Returns:
            AccountDeletionResult with deletion confirmation.
        """
        data = await self._request("DELETE", "/api/v1/account/data")
        return AccountDeletionResult.from_dict(data)

    async def export_account_data(self) -> AccountExportResult:
        """Export all account data as JSON (GDPR Article 20 — Right to Data Portability).

        Returns:
            AccountExportResult with full data export.
        """
        data = await self._request("GET", "/api/v1/account/export")
        return AccountExportResult.from_dict(data)

    async def record_consent(self, input: RecordConsentInput) -> ConsentActionResult:
        """Record user consent (GDPR Article 7).

        Args:
            input: Consent type and policy version.

        Returns:
            ConsentActionResult with the created consent record.
        """
        data = await self._request("POST", "/api/v1/account/consent", {
            "consent_type": input.consent_type.value if isinstance(input.consent_type, ConsentType) else input.consent_type,
            "version": input.version,
        })
        return ConsentActionResult.from_dict(data)

    async def get_consent_status(self, consent_type: Optional[ConsentType] = None) -> ConsentStatusResult:
        """Get current consent status (GDPR Article 7).

        Args:
            consent_type: Optional filter by consent type.

        Returns:
            ConsentStatusResult with list of consent records.
        """
        path = "/api/v1/account/consent"
        if consent_type:
            type_val = consent_type.value if isinstance(consent_type, ConsentType) else consent_type
            path += f"?type={type_val}"
        data = await self._request("GET", path)
        return ConsentStatusResult.from_dict(data)

    async def withdraw_consent(self, consent_type: ConsentType) -> ConsentActionResult:
        """Withdraw consent (GDPR Article 7.3).

        Args:
            consent_type: Type of consent to withdraw.

        Returns:
            ConsentActionResult with the withdrawal record.
        """
        type_val = consent_type.value if isinstance(consent_type, ConsentType) else consent_type
        data = await self._request("DELETE", f"/api/v1/account/consent/{type_val}")
        return ConsentActionResult.from_dict(data)

    async def rectify_data(self, input: RectifyDataInput) -> RectifyDataResult:
        """Rectify user data (GDPR Article 16 -- Right to Rectification).

        Args:
            input: Collection, document ID, and fields to update.

        Returns:
            RectifyDataResult with list of updated fields.
        """
        data = await self._request("PATCH", "/api/v1/account/data", {
            "collection": input.collection,
            "document_id": input.document_id,
            "fields": input.fields,
        })
        return RectifyDataResult.from_dict(data)

    async def get_audit_logs(
        self,
        action: Optional[AuditAction] = None,
        limit: Optional[int] = None,
    ) -> AuditLogsResult:
        """Get audit logs (GDPR Article 15 -- Right of Access).

        Args:
            action: Optional filter by action type.
            limit: Maximum number of results.

        Returns:
            AuditLogsResult with list of audit log entries.
        """
        params = []
        if action:
            action_val = action.value if isinstance(action, AuditAction) else action
            params.append(f"action={action_val}")
        if limit:
            params.append(f"limit={limit}")
        query = f"?{'&'.join(params)}" if params else ""
        data = await self._request("GET", f"/api/v1/account/audit-logs{query}")
        return AuditLogsResult.from_dict(data)

    # =========================================================================
    # Breach Management (GDPR Article 33/34)
    # =========================================================================

    async def log_breach(self, input: LogBreachInput) -> LogBreachResult:
        """Log a new data breach.

        Args:
            input: Breach details including title, severity, affected users.

        Returns:
            LogBreachResult with the created breach record.
        """
        data = await self._request("POST", "/api/v1/admin/breach", {
            "title": input.title,
            "description": input.description,
            "severity": input.severity.value if isinstance(input.severity, BreachSeverity) else input.severity,
            "affected_user_ids": input.affected_user_ids,
            "data_categories": input.data_categories,
            "reported_by": input.reported_by,
        })
        return LogBreachResult.from_dict(data)

    async def list_breaches(
        self,
        status: Optional[BreachStatus] = None,
        limit: Optional[int] = None,
    ) -> BreachListResult:
        """List data breaches.

        Args:
            status: Optional filter by breach status.
            limit: Maximum number of results.

        Returns:
            BreachListResult with list of breach records.
        """
        params = []
        if status:
            status_val = status.value if isinstance(status, BreachStatus) else status
            params.append(f"status={status_val}")
        if limit:
            params.append(f"limit={limit}")
        query = f"?{'&'.join(params)}" if params else ""
        data = await self._request("GET", f"/api/v1/admin/breach{query}")
        return BreachListResult.from_dict(data)

    async def get_breach(self, breach_id: str) -> BreachResult:
        """Get a single breach by ID.

        Args:
            breach_id: The breach ID.

        Returns:
            BreachResult with the breach record.
        """
        data = await self._request("GET", f"/api/v1/admin/breach/{breach_id}")
        return BreachResult.from_dict(data)

    async def update_breach_status(
        self,
        breach_id: str,
        input: UpdateBreachInput,
    ) -> BreachResult:
        """Update a breach's status.

        Args:
            breach_id: The breach ID.
            input: Status update details.

        Returns:
            BreachResult with the updated breach record.
        """
        body: dict[str, Any] = {
            "status": input.status.value if isinstance(input.status, BreachStatus) else input.status,
        }
        if input.notification_status:
            body["notification_status"] = input.notification_status.value if isinstance(input.notification_status, BreachNotificationStatus) else input.notification_status
        if input.notes:
            body["notes"] = input.notes
        data = await self._request("PATCH", f"/api/v1/admin/breach/{breach_id}", body)
        return BreachResult.from_dict(data)

    # =========================================================================
    # Private Methods
    # =========================================================================

    async def _request(
        self,
        method: str,
        path: str,
        body: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Make an API request with retry logic."""
        last_error: Optional[Exception] = None

        for attempt in range(self._max_retries):
            try:
                return await self._perform_request(method, path, body)
            except (AuthenticationError, ValidationError, NotFoundError):
                # Don't retry these errors
                raise
            except Exception as e:
                last_error = e
                if attempt < self._max_retries - 1:
                    delay = self._retry_delay * (2 ** attempt)
                    await asyncio.sleep(delay)

        raise last_error or TuteliqError("Request failed after retries")

    async def _perform_request(
        self,
        method: str,
        path: str,
        body: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Perform a single API request."""
        try:
            response = await self._client.request(method, path, json=body)
        except httpx.TimeoutException:
            raise TimeoutError(f"Request timed out after {self._timeout} seconds")
        except httpx.NetworkError as e:
            raise NetworkError(str(e))

        # Extract metadata from headers
        self.last_request_id = response.headers.get("x-request-id")

        # Monthly usage headers
        limit = response.headers.get("x-monthly-limit")
        used = response.headers.get("x-monthly-used")
        remaining = response.headers.get("x-monthly-remaining")

        if limit and used and remaining:
            self.usage = Usage(
                limit=int(limit),
                used=int(used),
                remaining=int(remaining),
            )

        # Handle errors
        if not response.is_success:
            self._handle_error_response(response)

        return response.json()

    def _handle_error_response(self, response: httpx.Response) -> None:
        """Handle error responses from the API."""
        try:
            data = response.json()
            message = data.get("error", {}).get("message", "Request failed")
            details = data.get("error", {}).get("details")
        except Exception:
            message = "Request failed"
            details = None

        status = response.status_code

        if status == 400:
            raise ValidationError(message, details)
        elif status == 401:
            raise AuthenticationError(message, details)
        elif status == 404:
            raise NotFoundError(message, details)
        elif status == 429:
            raise RateLimitError(message, details)
        elif status >= 500:
            raise ServerError(message, status, details)
        else:
            raise TuteliqError(message, details)
