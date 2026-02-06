<p align="center">
  <img src="./assets/logo.png" alt="SafeNest" width="200" />
</p>

<h1 align="center">SafeNest Python SDK</h1>

<p align="center">
  <strong>Official Python SDK for the SafeNest API</strong><br>
  AI-powered child safety analysis
</p>

<p align="center">
  <a href="https://pypi.org/project/safenest/"><img src="https://img.shields.io/pypi/v/safenest.svg" alt="PyPI version"></a>
  <a href="https://pypi.org/project/safenest/"><img src="https://img.shields.io/pypi/pyversions/safenest.svg" alt="Python versions"></a>
  <a href="https://github.com/SafeNestSDK/python/actions"><img src="https://img.shields.io/github/actions/workflow/status/SafeNestSDK/python/ci.yml" alt="build status"></a>
  <a href="https://github.com/SafeNestSDK/python/blob/main/LICENSE"><img src="https://img.shields.io/github/license/SafeNestSDK/python.svg" alt="license"></a>
</p>

<p align="center">
  <a href="https://api.safenest.dev/docs">API Docs</a> •
  <a href="https://safenest.app">Dashboard</a> •
  <a href="https://discord.gg/7kbTeRYRXD">Discord</a>
</p>

---

## Installation

```bash
pip install safenest
```

### Requirements

- Python 3.9+

---

## Quick Start

```python
import asyncio
from safenest import SafeNest

async def main():
    client = SafeNest(api_key="your-api-key")

    # Quick safety analysis
    result = await client.analyze("Message to check")

    if result.risk_level != RiskLevel.SAFE:
        print(f"Risk: {result.risk_level}")
        print(f"Summary: {result.summary}")

    await client.close()

asyncio.run(main())
```

Or use as a context manager:

```python
async with SafeNest(api_key="your-api-key") as client:
    result = await client.analyze("Message to check")
```

---

## API Reference

### Initialization

```python
from safenest import SafeNest

# Simple
client = SafeNest(api_key="your-api-key")

# With options
client = SafeNest(
    api_key="your-api-key",
    timeout=30.0,      # Request timeout in seconds
    max_retries=3,     # Retry attempts
    retry_delay=1.0,   # Initial retry delay in seconds
)
```

### Bullying Detection

```python
result = await client.detect_bullying("Nobody likes you, just leave")

if result.is_bullying:
    print(f"Severity: {result.severity}")       # Severity.MEDIUM
    print(f"Types: {result.bullying_type}")     # ["exclusion", "verbal_abuse"]
    print(f"Confidence: {result.confidence}")   # 0.92
    print(f"Rationale: {result.rationale}")
```

### Grooming Detection

```python
from safenest import DetectGroomingInput, GroomingMessage, MessageRole

result = await client.detect_grooming(
    DetectGroomingInput(
        messages=[
            GroomingMessage(role=MessageRole.ADULT, content="This is our secret"),
            GroomingMessage(role=MessageRole.CHILD, content="Ok I won't tell"),
        ],
        child_age=12,
    )
)

if result.grooming_risk == GroomingRisk.HIGH:
    print(f"Flags: {result.flags}")  # ["secrecy", "isolation"]
```

### Unsafe Content Detection

```python
result = await client.detect_unsafe("I don't want to be here anymore")

if result.unsafe:
    print(f"Categories: {result.categories}")  # ["self_harm", "crisis"]
    print(f"Severity: {result.severity}")      # Severity.CRITICAL
```

### Quick Analysis

Runs bullying and unsafe detection in parallel:

```python
result = await client.analyze("Message to check")

print(f"Risk Level: {result.risk_level}")   # RiskLevel.SAFE/LOW/MEDIUM/HIGH/CRITICAL
print(f"Risk Score: {result.risk_score}")   # 0.0 - 1.0
print(f"Summary: {result.summary}")
print(f"Action: {result.recommended_action}")
```

### Emotion Analysis

```python
result = await client.analyze_emotions("I'm so stressed about everything")

print(f"Emotions: {result.dominant_emotions}")  # ["anxiety", "sadness"]
print(f"Trend: {result.trend}")                 # EmotionTrend.WORSENING
print(f"Followup: {result.recommended_followup}")
```

### Action Plan

```python
from safenest import GetActionPlanInput, Audience, Severity

plan = await client.get_action_plan(
    GetActionPlanInput(
        situation="Someone is spreading rumors about me",
        child_age=12,
        audience=Audience.CHILD,
        severity=Severity.MEDIUM,
    )
)

print(f"Steps: {plan.steps}")
print(f"Tone: {plan.tone}")
```

### Incident Report

```python
from safenest import GenerateReportInput, ReportMessage

report = await client.generate_report(
    GenerateReportInput(
        messages=[
            ReportMessage(sender="user1", content="Threatening message"),
            ReportMessage(sender="child", content="Please stop"),
        ],
        child_age=14,
    )
)

print(f"Summary: {report.summary}")
print(f"Risk: {report.risk_level}")
print(f"Next Steps: {report.recommended_next_steps}")
```

---

## Tracking Fields

All methods support `external_id` and `metadata` for correlating requests:

```python
result = await client.detect_bullying(
    "Test message",
    external_id="msg_12345",
    metadata={"user_id": "usr_abc", "session": "sess_xyz"},
)

# Echoed back in response
print(result.external_id)  # "msg_12345"
print(result.metadata)     # {"user_id": "usr_abc", ...}
```

---

## Usage Tracking

```python
result = await client.detect_bullying("test")

# Access usage stats after any request
if client.usage:
    print(f"Limit: {client.usage.limit}")
    print(f"Used: {client.usage.used}")
    print(f"Remaining: {client.usage.remaining}")

# Request metadata
print(f"Request ID: {client.last_request_id}")
```

---

## Error Handling

```python
from safenest import (
    SafeNest,
    SafeNestError,
    AuthenticationError,
    RateLimitError,
    ValidationError,
    NotFoundError,
    ServerError,
    TimeoutError,
    NetworkError,
)

try:
    result = await client.detect_bullying("test")
except AuthenticationError as e:
    print(f"Auth error: {e.message}")
except RateLimitError as e:
    print(f"Rate limited: {e.message}")
except ValidationError as e:
    print(f"Invalid input: {e.message}, details: {e.details}")
except ServerError as e:
    print(f"Server error {e.status_code}: {e.message}")
except TimeoutError as e:
    print(f"Timeout: {e.message}")
except NetworkError as e:
    print(f"Network error: {e.message}")
except SafeNestError as e:
    print(f"Error: {e.message}")
```

---

## Type Hints

The SDK is fully typed. All models are dataclasses with type hints:

```python
from safenest import (
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
    # Message types
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
)
```

---

## FastAPI Example

```python
from fastapi import FastAPI, HTTPException
from safenest import SafeNest, RateLimitError

app = FastAPI()
client = SafeNest(api_key="your-api-key")

@app.post("/check-message")
async def check_message(message: str):
    try:
        result = await client.analyze(message)

        if result.risk_level.value in ["high", "critical"]:
            raise HTTPException(
                status_code=400,
                detail={"error": "Message blocked", "reason": result.summary}
            )

        return {"safe": True, "risk_level": result.risk_level.value}

    except RateLimitError:
        raise HTTPException(status_code=429, detail="Too many requests")
```

---

## Support

- **API Docs**: [api.safenest.dev/docs](https://api.safenest.dev/docs)
- **Discord**: [discord.gg/7kbTeRYRXD](https://discord.gg/7kbTeRYRXD)
- **Email**: support@safenest.dev
- **Issues**: [GitHub Issues](https://github.com/SafeNestSDK/python/issues)

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

<p align="center">
  <sub>Built with care for child safety by the <a href="https://safenest.dev">SafeNest</a> team</sub>
</p>
