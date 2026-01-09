# Scam Detection Agent

AI-powered scam pattern detection for forum posts using OpenAI-compatible LLM APIs.

## Overview

This library provides a flexible scam detection system that:

- Integrates with any **OpenAI-compatible API** (LM Studio, Ollama, vLLM, OpenAI, etc.)
- Defines scam patterns in **plain English** for easy customization
- Uses LLM-based analysis for nuanced pattern matching
- Returns structured results with confidence scores and evidence

## Installation

```bash
pip install -e .

# Or install dependencies directly
pip install httpx pydantic
```

## Quick Start

```python
from scam_detector import (
    OpenAIClient,
    ScamDetector,
    Post,
    get_common_patterns,
)

# Connect to your LLM (LM Studio example)
client = OpenAIClient(
    base_url="http://localhost:1234/v1",
    model="local-model",
)

# Create detector with pre-defined patterns
detector = ScamDetector(client, patterns=get_common_patterns())

# Analyze a post
post = Post(
    content="You've won $1,000,000! Pay $500 to claim your prize!",
    title="CONGRATULATIONS!!!",
)

result = detector.analyze(post)

print(f"Risk: {result.risk_level}")  # Risk: high
print(f"Is scam: {result.is_scam}")  # Is scam: True
print(f"Summary: {result.summary}")

for match in result.matched_patterns:
    print(f"  - {match.pattern_name}: {match.confidence:.0%}")
```

## Configuring the LLM Client

The `OpenAIClient` works with any OpenAI-compatible endpoint:

```python
# LM Studio (default)
client = OpenAIClient(
    base_url="http://localhost:1234/v1",
    model="local-model",
)

# Ollama
client = OpenAIClient(
    base_url="http://localhost:11434/v1",
    model="llama2",
)

# OpenAI
client = OpenAIClient(
    base_url="https://api.openai.com/v1",
    api_key="sk-...",
    model="gpt-4",
)

# vLLM / text-generation-inference
client = OpenAIClient(
    base_url="http://localhost:8000/v1",
    model="meta-llama/Llama-2-7b-chat-hf",
)
```

## Scam Patterns

Patterns are defined in plain English, making them easy to customize:

```python
from scam_detector import ScamPattern, RiskLevel

# Create a custom pattern
my_pattern = ScamPattern(
    name="fake_giveaway",
    description="""
    Social media giveaway scam where users are asked to send cryptocurrency
    to receive more back, or share personal information to claim a prize.
    """,
    indicators=[
        "Promise of free cryptocurrency",
        "Requirement to send crypto first",
        "Impersonation of celebrities or companies",
        "Urgency and limited time claims",
    ],
    severity=RiskLevel.HIGH,
    examples=[
        "Send 0.1 ETH, get 1 ETH back!",
        "Elon is giving away Bitcoin! First 1000 people only!",
    ],
)

# Add to detector
detector.add_pattern(my_pattern)
```

### Pre-defined Patterns

The library includes common scam patterns:

| Pattern | Description |
|---------|-------------|
| `ADVANCE_FEE_SCAM` | Pay fee to receive larger sum |
| `CRYPTO_PUMP_AND_DUMP` | Artificial crypto price inflation |
| `FAKE_INVESTMENT` | Ponzi schemes, guaranteed returns |
| `FAKE_BUYER` | Overpayment scams targeting sellers |
| `FAKE_SELLER` | Non-delivery after payment |
| `ROMANCE_SCAM` | Emotional manipulation for money |
| `FAKE_JOB` | Employment scams |
| `MONEY_MULE` | Laundering recruitment |
| `TECH_SUPPORT_SCAM` | Fake support requests |
| `PHISHING` | Credential theft attempts |

Use helper functions to get pattern groups:

```python
from scam_detector import (
    get_common_patterns,      # All patterns
    get_financial_patterns,   # Investment/crypto scams
    get_marketplace_patterns, # Buyer/seller fraud
    get_employment_patterns,  # Job scams
    get_tech_patterns,        # Phishing/tech support
)
```

## Detection Results

The `DetectionResult` provides detailed analysis:

```python
result = detector.analyze(post)

# Overall assessment
result.risk_level      # RiskLevel enum: NONE, LOW, MEDIUM, HIGH, CRITICAL
result.is_scam         # True if any patterns matched
result.summary         # Human-readable summary

# Pattern matches
for match in result.matched_patterns:
    match.pattern_name  # Which pattern matched
    match.confidence    # 0.0 to 1.0
    match.evidence      # Specific text that triggered match
    match.explanation   # Why the pattern matched

# Convenience
result.highest_confidence_match  # Pattern with highest confidence
```

## Async Support

For high-throughput applications:

```python
import asyncio
from scam_detector import OpenAIClient, ScamDetector, Post

async def analyze_posts(posts):
    async with OpenAIClient() as client:
        detector = ScamDetector(client, patterns=get_common_patterns())

        # Analyze concurrently
        results = await detector.aanalyze_batch(posts)

        for post, result in zip(posts, results):
            if result.is_scam:
                print(f"Warning: {result.summary}")

asyncio.run(analyze_posts(my_posts))
```

## Web Interface

The library includes a web-based interface for testing and configuring the scam detector.

### Running the Web Interface

```bash
# Install web dependencies
pip install fastapi uvicorn python-multipart

# Run the web server
python -m scam_detector.web

# Or with uvicorn directly
uvicorn scam_detector.web.app:app --reload
```

Then open http://localhost:8000 in your browser.

### Web Interface Features

- **Analyze Messages**: Paste messages to test for scam patterns with detailed results
- **Manage Patterns**: Add, edit, and delete scam patterns through the UI
- **Import/Export**: Download patterns as JSON files or upload pattern files
- **Configure LLM**: Set the LLM provider URL, API key, model, and parameters

### API Endpoints

The web interface also exposes a REST API:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/analyze` | POST | Analyze a message for scams |
| `/api/patterns` | GET | List all patterns |
| `/api/patterns` | POST | Create a new pattern |
| `/api/patterns/{name}` | PUT | Update a pattern |
| `/api/patterns/{name}` | DELETE | Delete a pattern |
| `/api/patterns/export` | GET | Download patterns as JSON |
| `/api/patterns/import` | POST | Upload patterns from JSON |
| `/api/patterns/reset` | POST | Reset to default patterns |
| `/api/config` | GET | Get LLM configuration |
| `/api/config` | PUT | Update LLM configuration |

## Project Structure

```
scam_detector/
├── __init__.py      # Public API exports
├── models.py        # Data models (Post, Pattern, Result)
├── client.py        # OpenAI-compatible API client
├── detector.py      # Detection engine
├── patterns.py      # Pre-defined scam patterns
└── web/             # Web interface
    ├── __init__.py
    ├── __main__.py  # Entry point for running web server
    ├── app.py       # FastAPI application
    └── static/      # Frontend assets
        ├── index.html
        ├── styles.css
        └── app.js

examples/
├── basic_usage.py   # Synchronous usage examples
└── async_usage.py   # Async/batch processing examples

tests/
├── test_models.py   # Model unit tests
├── test_client.py   # API client tests
└── test_detector.py # Detection engine tests
```

## Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# With coverage
pytest --cov=scam_detector
```

## API Reference

### OpenAIClient

```python
OpenAIClient(
    base_url: str = "http://localhost:1234/v1",
    api_key: str | None = None,
    model: str = "local-model",
    timeout: float = 120.0,
    max_tokens: int = 2048,
    temperature: float = 0.1,
)
```

### ScamDetector

```python
ScamDetector(
    client: OpenAIClient,
    patterns: list[ScamPattern] | None = None,
)

# Methods
detector.analyze(post: Post) -> DetectionResult
detector.analyze_text(text: str) -> DetectionResult
detector.analyze_batch(posts: list[Post]) -> list[DetectionResult]

# Async variants
await detector.aanalyze(post)
await detector.aanalyze_text(text)
await detector.aanalyze_batch(posts)

# Pattern management
detector.add_pattern(pattern)
detector.add_patterns(patterns)
detector.remove_pattern(name) -> bool
detector.clear_patterns()
```

### ScamPattern

```python
ScamPattern(
    name: str,                          # Identifier
    description: str,                   # Plain English description
    indicators: list[str] = [],         # Red flags to look for
    severity: RiskLevel = MEDIUM,       # Default severity
    examples: list[str] = [],           # Example phrases
)
```

### Post

```python
Post(
    content: str,                       # Post body text
    title: str | None = None,           # Optional title
    author: str | None = None,          # Optional author
    metadata: dict = {},                # Additional context
)
```

## License

MIT
