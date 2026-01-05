"""Data models for the scam detection system."""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    """Risk level classification for detected scam patterns."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScamPattern(BaseModel):
    """A scam pattern definition described in plain English.

    Patterns are described naturally so the LLM can understand
    and match them against post content.
    """

    name: str = Field(..., description="Short identifier for the pattern")
    description: str = Field(
        ...,
        description="Plain English description of the scam pattern"
    )
    indicators: list[str] = Field(
        default_factory=list,
        description="Specific indicators or red flags to look for"
    )
    severity: RiskLevel = Field(
        default=RiskLevel.MEDIUM,
        description="Default severity if this pattern is detected"
    )
    examples: list[str] = Field(
        default_factory=list,
        description="Example phrases or scenarios that match this pattern"
    )

    def to_prompt_section(self) -> str:
        """Convert pattern to a prompt section for the LLM."""
        sections = [
            f"Pattern: {self.name}",
            f"Description: {self.description}",
        ]

        if self.indicators:
            indicators_text = "\n".join(f"  - {ind}" for ind in self.indicators)
            sections.append(f"Indicators:\n{indicators_text}")

        if self.examples:
            examples_text = "\n".join(f"  - \"{ex}\"" for ex in self.examples)
            sections.append(f"Examples:\n{examples_text}")

        sections.append(f"Severity: {self.severity.value}")

        return "\n".join(sections)


class Post(BaseModel):
    """A forum post to be analyzed for scam patterns."""

    content: str = Field(..., description="The text content of the post")
    author: Optional[str] = Field(None, description="Author/username if available")
    title: Optional[str] = Field(None, description="Post title if available")
    metadata: dict = Field(
        default_factory=dict,
        description="Additional metadata (timestamp, source, etc.)"
    )

    def to_analysis_text(self) -> str:
        """Convert post to text for analysis."""
        parts = []

        if self.title:
            parts.append(f"Title: {self.title}")

        if self.author:
            parts.append(f"Author: {self.author}")

        parts.append(f"Content: {self.content}")

        return "\n".join(parts)


class PatternMatch(BaseModel):
    """A matched scam pattern with analysis details."""

    pattern_name: str = Field(..., description="Name of the matched pattern")
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score (0.0 to 1.0)"
    )
    evidence: list[str] = Field(
        default_factory=list,
        description="Specific text/elements that triggered the match"
    )
    explanation: str = Field(
        default="",
        description="LLM explanation of why this pattern was matched"
    )


class DetectionResult(BaseModel):
    """Complete result of scam detection analysis."""

    post: Post = Field(..., description="The analyzed post")
    risk_level: RiskLevel = Field(..., description="Overall risk assessment")
    matched_patterns: list[PatternMatch] = Field(
        default_factory=list,
        description="List of matched scam patterns"
    )
    summary: str = Field(
        default="",
        description="Human-readable summary of the analysis"
    )
    raw_response: Optional[str] = Field(
        None,
        description="Raw LLM response for debugging"
    )

    @property
    def is_scam(self) -> bool:
        """Check if any scam patterns were detected."""
        return len(self.matched_patterns) > 0

    @property
    def highest_confidence_match(self) -> Optional[PatternMatch]:
        """Get the pattern match with highest confidence."""
        if not self.matched_patterns:
            return None
        return max(self.matched_patterns, key=lambda m: m.confidence)
