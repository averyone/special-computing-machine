"""Scam detection engine using LLM-based pattern matching."""

import json
from typing import Optional

from .client import OpenAIClient, ChatMessage
from .models import (
    ScamPattern,
    Post,
    DetectionResult,
    PatternMatch,
    RiskLevel,
)


SYSTEM_PROMPT = """You are a scam detection expert analyzing forum posts for potential scam patterns.

Your task is to carefully analyze the given post and determine if it matches any of the provided scam patterns.

Be thorough but avoid false positives. Only flag content that genuinely matches the scam patterns.
Consider context and nuance - legitimate posts may superficially resemble scams.

You must respond with a valid JSON object in the following format:
{
    "risk_level": "none" | "low" | "medium" | "high" | "critical",
    "matched_patterns": [
        {
            "pattern_name": "name of the matched pattern",
            "confidence": 0.0 to 1.0,
            "evidence": ["specific text or elements that triggered this match"],
            "explanation": "why this pattern was matched"
        }
    ],
    "summary": "brief human-readable summary of the analysis"
}

Guidelines for risk levels:
- none: No scam indicators detected
- low: Minor red flags, possibly legitimate
- medium: Several concerning indicators, warrants caution
- high: Strong scam indicators, likely fraudulent
- critical: Clear and obvious scam attempt

Guidelines for confidence scores:
- 0.0-0.3: Weak match, possibly coincidental
- 0.4-0.6: Moderate match, some indicators present
- 0.7-0.8: Strong match, multiple clear indicators
- 0.9-1.0: Very strong match, unmistakable pattern"""


class ScamDetector:
    """AI-powered scam detection engine.

    Uses LLM-based analysis to match posts against defined scam patterns.
    Patterns are described in plain English for flexibility.
    """

    def __init__(
        self,
        client: OpenAIClient,
        patterns: Optional[list[ScamPattern]] = None,
    ):
        """Initialize the scam detector.

        Args:
            client: OpenAI-compatible API client
            patterns: List of scam patterns to detect (can be added later)
        """
        self.client = client
        self.patterns: list[ScamPattern] = patterns or []

    def add_pattern(self, pattern: ScamPattern) -> None:
        """Add a scam pattern to the detector."""
        self.patterns.append(pattern)

    def add_patterns(self, patterns: list[ScamPattern]) -> None:
        """Add multiple scam patterns to the detector."""
        self.patterns.extend(patterns)

    def remove_pattern(self, name: str) -> bool:
        """Remove a pattern by name. Returns True if found and removed."""
        for i, pattern in enumerate(self.patterns):
            if pattern.name == name:
                self.patterns.pop(i)
                return True
        return False

    def clear_patterns(self) -> None:
        """Remove all patterns."""
        self.patterns.clear()

    def _build_patterns_prompt(self) -> str:
        """Build the patterns section of the prompt."""
        if not self.patterns:
            return "No specific patterns defined. Use general scam detection heuristics."

        sections = ["SCAM PATTERNS TO DETECT:\n"]
        for i, pattern in enumerate(self.patterns, 1):
            sections.append(f"--- Pattern {i} ---")
            sections.append(pattern.to_prompt_section())
            sections.append("")

        return "\n".join(sections)

    def _build_analysis_prompt(self, post: Post) -> str:
        """Build the complete analysis prompt."""
        return f"""{self._build_patterns_prompt()}

POST TO ANALYZE:
{post.to_analysis_text()}

Analyze this post against the patterns above. Respond with JSON only."""

    def _parse_result(
        self,
        post: Post,
        response: str,
    ) -> DetectionResult:
        """Parse the LLM response into a DetectionResult."""
        try:
            data = self.client._parse_json_response(response)

            matched_patterns = [
                PatternMatch(
                    pattern_name=m.get("pattern_name", "unknown"),
                    confidence=float(m.get("confidence", 0.5)),
                    evidence=m.get("evidence", []),
                    explanation=m.get("explanation", ""),
                )
                for m in data.get("matched_patterns", [])
            ]

            risk_str = data.get("risk_level", "none").lower()
            try:
                risk_level = RiskLevel(risk_str)
            except ValueError:
                # Map unknown risk levels
                risk_level = RiskLevel.MEDIUM if matched_patterns else RiskLevel.NONE

            return DetectionResult(
                post=post,
                risk_level=risk_level,
                matched_patterns=matched_patterns,
                summary=data.get("summary", ""),
                raw_response=response,
            )

        except (json.JSONDecodeError, KeyError, TypeError) as e:
            # If parsing fails, return a result indicating the issue
            return DetectionResult(
                post=post,
                risk_level=RiskLevel.NONE,
                matched_patterns=[],
                summary=f"Analysis failed: {e}",
                raw_response=response,
            )

    def analyze(self, post: Post, **kwargs) -> DetectionResult:
        """Analyze a post for scam patterns (synchronous).

        Args:
            post: The post to analyze
            **kwargs: Additional parameters passed to the LLM

        Returns:
            DetectionResult with matched patterns and risk assessment
        """
        messages = [
            ChatMessage(role="system", content=SYSTEM_PROMPT),
            ChatMessage(role="user", content=self._build_analysis_prompt(post)),
        ]

        response = self.client.chat(messages, **kwargs)
        return self._parse_result(post, response)

    async def aanalyze(self, post: Post, **kwargs) -> DetectionResult:
        """Analyze a post for scam patterns (asynchronous).

        Args:
            post: The post to analyze
            **kwargs: Additional parameters passed to the LLM

        Returns:
            DetectionResult with matched patterns and risk assessment
        """
        messages = [
            ChatMessage(role="system", content=SYSTEM_PROMPT),
            ChatMessage(role="user", content=self._build_analysis_prompt(post)),
        ]

        response = await self.client.achat(messages, **kwargs)
        return self._parse_result(post, response)

    def analyze_text(self, text: str, **kwargs) -> DetectionResult:
        """Convenience method to analyze plain text.

        Args:
            text: The text content to analyze
            **kwargs: Additional parameters passed to the LLM

        Returns:
            DetectionResult with matched patterns and risk assessment
        """
        post = Post(content=text)
        return self.analyze(post, **kwargs)

    async def aanalyze_text(self, text: str, **kwargs) -> DetectionResult:
        """Async convenience method to analyze plain text.

        Args:
            text: The text content to analyze
            **kwargs: Additional parameters passed to the LLM

        Returns:
            DetectionResult with matched patterns and risk assessment
        """
        post = Post(content=text)
        return await self.aanalyze(post, **kwargs)

    def analyze_batch(
        self,
        posts: list[Post],
        **kwargs,
    ) -> list[DetectionResult]:
        """Analyze multiple posts sequentially.

        Args:
            posts: List of posts to analyze
            **kwargs: Additional parameters passed to the LLM

        Returns:
            List of DetectionResults in the same order as input
        """
        return [self.analyze(post, **kwargs) for post in posts]

    async def aanalyze_batch(
        self,
        posts: list[Post],
        **kwargs,
    ) -> list[DetectionResult]:
        """Analyze multiple posts asynchronously.

        Args:
            posts: List of posts to analyze
            **kwargs: Additional parameters passed to the LLM

        Returns:
            List of DetectionResults in the same order as input
        """
        import asyncio
        tasks = [self.aanalyze(post, **kwargs) for post in posts]
        return await asyncio.gather(*tasks)
