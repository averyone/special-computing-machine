"""Tests for data models."""

import pytest
from scam_detector.models import (
    ScamPattern,
    Post,
    DetectionResult,
    PatternMatch,
    RiskLevel,
)


class TestScamPattern:
    """Tests for ScamPattern model."""

    def test_basic_creation(self):
        """Test creating a basic pattern."""
        pattern = ScamPattern(
            name="test_pattern",
            description="A test scam pattern",
        )
        assert pattern.name == "test_pattern"
        assert pattern.description == "A test scam pattern"
        assert pattern.severity == RiskLevel.MEDIUM
        assert pattern.indicators == []
        assert pattern.examples == []

    def test_full_creation(self):
        """Test creating a pattern with all fields."""
        pattern = ScamPattern(
            name="full_pattern",
            description="Complete pattern",
            indicators=["indicator1", "indicator2"],
            severity=RiskLevel.HIGH,
            examples=["example1", "example2"],
        )
        assert pattern.name == "full_pattern"
        assert len(pattern.indicators) == 2
        assert pattern.severity == RiskLevel.HIGH
        assert len(pattern.examples) == 2

    def test_to_prompt_section(self):
        """Test converting pattern to prompt section."""
        pattern = ScamPattern(
            name="test",
            description="Test description",
            indicators=["ind1"],
            examples=["ex1"],
            severity=RiskLevel.HIGH,
        )
        prompt = pattern.to_prompt_section()

        assert "Pattern: test" in prompt
        assert "Description: Test description" in prompt
        assert "ind1" in prompt
        assert "ex1" in prompt
        assert "high" in prompt


class TestPost:
    """Tests for Post model."""

    def test_basic_creation(self):
        """Test creating a basic post."""
        post = Post(content="Test content")
        assert post.content == "Test content"
        assert post.author is None
        assert post.title is None
        assert post.metadata == {}

    def test_full_creation(self):
        """Test creating a post with all fields."""
        post = Post(
            content="Full content",
            author="test_user",
            title="Test Title",
            metadata={"source": "forum"},
        )
        assert post.content == "Full content"
        assert post.author == "test_user"
        assert post.title == "Test Title"
        assert post.metadata["source"] == "forum"

    def test_to_analysis_text(self):
        """Test converting post to analysis text."""
        post = Post(
            content="Main content",
            author="user",
            title="Title",
        )
        text = post.to_analysis_text()

        assert "Title: Title" in text
        assert "Author: user" in text
        assert "Content: Main content" in text

    def test_to_analysis_text_minimal(self):
        """Test analysis text with only content."""
        post = Post(content="Just content")
        text = post.to_analysis_text()

        assert "Content: Just content" in text
        assert "Title:" not in text
        assert "Author:" not in text


class TestPatternMatch:
    """Tests for PatternMatch model."""

    def test_basic_creation(self):
        """Test creating a basic match."""
        match = PatternMatch(
            pattern_name="test",
            confidence=0.8,
        )
        assert match.pattern_name == "test"
        assert match.confidence == 0.8
        assert match.evidence == []
        assert match.explanation == ""

    def test_confidence_bounds(self):
        """Test confidence must be between 0 and 1."""
        # Valid values
        PatternMatch(pattern_name="test", confidence=0.0)
        PatternMatch(pattern_name="test", confidence=1.0)
        PatternMatch(pattern_name="test", confidence=0.5)

        # Invalid values
        with pytest.raises(ValueError):
            PatternMatch(pattern_name="test", confidence=-0.1)

        with pytest.raises(ValueError):
            PatternMatch(pattern_name="test", confidence=1.1)


class TestDetectionResult:
    """Tests for DetectionResult model."""

    def test_basic_creation(self):
        """Test creating a basic result."""
        post = Post(content="Test")
        result = DetectionResult(
            post=post,
            risk_level=RiskLevel.NONE,
        )
        assert result.post == post
        assert result.risk_level == RiskLevel.NONE
        assert result.matched_patterns == []
        assert result.summary == ""
        assert result.raw_response is None

    def test_is_scam_property(self):
        """Test is_scam property."""
        post = Post(content="Test")

        # No matches = not a scam
        result = DetectionResult(post=post, risk_level=RiskLevel.NONE)
        assert result.is_scam is False

        # With matches = is a scam
        result_with_match = DetectionResult(
            post=post,
            risk_level=RiskLevel.HIGH,
            matched_patterns=[
                PatternMatch(pattern_name="test", confidence=0.9)
            ],
        )
        assert result_with_match.is_scam is True

    def test_highest_confidence_match(self):
        """Test highest_confidence_match property."""
        post = Post(content="Test")

        # No matches
        result = DetectionResult(post=post, risk_level=RiskLevel.NONE)
        assert result.highest_confidence_match is None

        # Multiple matches
        matches = [
            PatternMatch(pattern_name="low", confidence=0.3),
            PatternMatch(pattern_name="high", confidence=0.9),
            PatternMatch(pattern_name="med", confidence=0.6),
        ]
        result = DetectionResult(
            post=post,
            risk_level=RiskLevel.HIGH,
            matched_patterns=matches,
        )
        assert result.highest_confidence_match.pattern_name == "high"
        assert result.highest_confidence_match.confidence == 0.9


class TestRiskLevel:
    """Tests for RiskLevel enum."""

    def test_values(self):
        """Test all risk level values exist."""
        assert RiskLevel.NONE.value == "none"
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.MEDIUM.value == "medium"
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.CRITICAL.value == "critical"

    def test_from_string(self):
        """Test creating from string value."""
        assert RiskLevel("none") == RiskLevel.NONE
        assert RiskLevel("high") == RiskLevel.HIGH
