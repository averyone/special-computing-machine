"""Tests for the scam detection engine."""

import json
import pytest
import httpx
import respx

from scam_detector import (
    OpenAIClient,
    ScamDetector,
    ScamPattern,
    Post,
    RiskLevel,
    get_common_patterns,
    CRYPTO_PUMP_AND_DUMP,
    ADVANCE_FEE_SCAM,
)


class TestScamDetector:
    """Tests for ScamDetector."""

    def test_initialization_without_patterns(self):
        """Test initializing detector without patterns."""
        client = OpenAIClient()
        detector = ScamDetector(client)
        assert detector.patterns == []
        client.close()

    def test_initialization_with_patterns(self):
        """Test initializing detector with patterns."""
        client = OpenAIClient()
        patterns = [CRYPTO_PUMP_AND_DUMP, ADVANCE_FEE_SCAM]
        detector = ScamDetector(client, patterns=patterns)
        assert len(detector.patterns) == 2
        client.close()

    def test_add_pattern(self):
        """Test adding a single pattern."""
        client = OpenAIClient()
        detector = ScamDetector(client)

        detector.add_pattern(CRYPTO_PUMP_AND_DUMP)
        assert len(detector.patterns) == 1
        assert detector.patterns[0].name == "crypto_pump_dump"
        client.close()

    def test_add_patterns(self):
        """Test adding multiple patterns."""
        client = OpenAIClient()
        detector = ScamDetector(client)

        detector.add_patterns([CRYPTO_PUMP_AND_DUMP, ADVANCE_FEE_SCAM])
        assert len(detector.patterns) == 2
        client.close()

    def test_remove_pattern(self):
        """Test removing a pattern by name."""
        client = OpenAIClient()
        detector = ScamDetector(client, patterns=[CRYPTO_PUMP_AND_DUMP])

        result = detector.remove_pattern("crypto_pump_dump")
        assert result is True
        assert len(detector.patterns) == 0

        # Try to remove non-existent pattern
        result = detector.remove_pattern("nonexistent")
        assert result is False
        client.close()

    def test_clear_patterns(self):
        """Test clearing all patterns."""
        client = OpenAIClient()
        detector = ScamDetector(client, patterns=get_common_patterns())

        assert len(detector.patterns) > 0
        detector.clear_patterns()
        assert len(detector.patterns) == 0
        client.close()

    def test_build_patterns_prompt_empty(self):
        """Test building prompt with no patterns."""
        client = OpenAIClient()
        detector = ScamDetector(client)

        prompt = detector._build_patterns_prompt()
        assert "No specific patterns defined" in prompt
        client.close()

    def test_build_patterns_prompt_with_patterns(self):
        """Test building prompt with patterns."""
        client = OpenAIClient()
        detector = ScamDetector(client, patterns=[CRYPTO_PUMP_AND_DUMP])

        prompt = detector._build_patterns_prompt()
        assert "SCAM PATTERNS TO DETECT" in prompt
        assert "crypto_pump_dump" in prompt
        client.close()

    def test_build_analysis_prompt(self):
        """Test building complete analysis prompt."""
        client = OpenAIClient()
        detector = ScamDetector(client, patterns=[ADVANCE_FEE_SCAM])

        post = Post(
            content="You won a prize!",
            title="Congratulations!",
            author="scammer",
        )
        prompt = detector._build_analysis_prompt(post)

        assert "advance_fee" in prompt
        assert "You won a prize!" in prompt
        assert "Congratulations!" in prompt
        assert "Respond with JSON only" in prompt
        client.close()

    def test_parse_result_success(self):
        """Test parsing a successful LLM response."""
        client = OpenAIClient()
        detector = ScamDetector(client)

        post = Post(content="Test post")
        response = json.dumps({
            "risk_level": "high",
            "matched_patterns": [
                {
                    "pattern_name": "test_pattern",
                    "confidence": 0.85,
                    "evidence": ["suspicious text"],
                    "explanation": "This matches the pattern",
                }
            ],
            "summary": "Likely a scam",
        })

        result = detector._parse_result(post, response)

        assert result.risk_level == RiskLevel.HIGH
        assert len(result.matched_patterns) == 1
        assert result.matched_patterns[0].pattern_name == "test_pattern"
        assert result.matched_patterns[0].confidence == 0.85
        assert result.summary == "Likely a scam"
        assert result.raw_response == response
        client.close()

    def test_parse_result_invalid_json(self):
        """Test parsing when LLM returns invalid JSON."""
        client = OpenAIClient()
        detector = ScamDetector(client)

        post = Post(content="Test post")
        response = "This is not valid JSON at all"

        result = detector._parse_result(post, response)

        assert result.risk_level == RiskLevel.NONE
        assert len(result.matched_patterns) == 0
        assert "failed" in result.summary.lower()
        client.close()

    def test_parse_result_unknown_risk_level(self):
        """Test parsing with unknown risk level."""
        client = OpenAIClient()
        detector = ScamDetector(client)

        post = Post(content="Test post")
        response = json.dumps({
            "risk_level": "unknown_level",
            "matched_patterns": [
                {"pattern_name": "test", "confidence": 0.5}
            ],
            "summary": "Test",
        })

        result = detector._parse_result(post, response)

        # Should default to MEDIUM when patterns matched
        assert result.risk_level == RiskLevel.MEDIUM
        client.close()

    @respx.mock
    def test_analyze_scam_post(self):
        """Test analyzing a scam post."""
        mock_response = {
            "risk_level": "high",
            "matched_patterns": [
                {
                    "pattern_name": "crypto_pump_dump",
                    "confidence": 0.9,
                    "evidence": ["going to 100x", "buy now"],
                    "explanation": "Classic pump and dump language",
                }
            ],
            "summary": "Highly suspicious crypto promotion",
        }

        respx.post("http://localhost:1234/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={
                    "choices": [
                        {"message": {"content": json.dumps(mock_response)}}
                    ]
                },
            )
        )

        client = OpenAIClient()
        detector = ScamDetector(client, patterns=[CRYPTO_PUMP_AND_DUMP])

        post = Post(
            content="This coin is going to 100x! Buy now before it's too late!",
            title="🚀 MOONSHOT ALERT 🚀",
        )
        result = detector.analyze(post)

        assert result.is_scam is True
        assert result.risk_level == RiskLevel.HIGH
        assert len(result.matched_patterns) == 1
        assert result.matched_patterns[0].pattern_name == "crypto_pump_dump"
        client.close()

    @respx.mock
    def test_analyze_legitimate_post(self):
        """Test analyzing a legitimate post."""
        mock_response = {
            "risk_level": "none",
            "matched_patterns": [],
            "summary": "Normal discussion about investing",
        }

        respx.post("http://localhost:1234/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={
                    "choices": [
                        {"message": {"content": json.dumps(mock_response)}}
                    ]
                },
            )
        )

        client = OpenAIClient()
        detector = ScamDetector(client, patterns=get_common_patterns())

        post = Post(
            content="What's a good index fund for long-term investing?",
            title="Investment advice needed",
        )
        result = detector.analyze(post)

        assert result.is_scam is False
        assert result.risk_level == RiskLevel.NONE
        assert len(result.matched_patterns) == 0
        client.close()

    @respx.mock
    def test_analyze_text_convenience(self):
        """Test the analyze_text convenience method."""
        mock_response = {
            "risk_level": "low",
            "matched_patterns": [],
            "summary": "Low risk content",
        }

        respx.post("http://localhost:1234/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={
                    "choices": [
                        {"message": {"content": json.dumps(mock_response)}}
                    ]
                },
            )
        )

        client = OpenAIClient()
        detector = ScamDetector(client)

        result = detector.analyze_text("Just some regular text here.")

        assert result.post.content == "Just some regular text here."
        assert result.risk_level == RiskLevel.LOW
        client.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_aanalyze(self):
        """Test async analysis."""
        mock_response = {
            "risk_level": "medium",
            "matched_patterns": [],
            "summary": "Async test",
        }

        respx.post("http://localhost:1234/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={
                    "choices": [
                        {"message": {"content": json.dumps(mock_response)}}
                    ]
                },
            )
        )

        async with OpenAIClient() as client:
            detector = ScamDetector(client)
            post = Post(content="Async test content")
            result = await detector.aanalyze(post)

            assert result.risk_level == RiskLevel.MEDIUM

    @respx.mock
    def test_analyze_batch(self):
        """Test batch analysis."""
        mock_response = {
            "risk_level": "none",
            "matched_patterns": [],
            "summary": "Clean",
        }

        respx.post("http://localhost:1234/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={
                    "choices": [
                        {"message": {"content": json.dumps(mock_response)}}
                    ]
                },
            )
        )

        client = OpenAIClient()
        detector = ScamDetector(client)

        posts = [
            Post(content="Post 1"),
            Post(content="Post 2"),
            Post(content="Post 3"),
        ]
        results = detector.analyze_batch(posts)

        assert len(results) == 3
        for result in results:
            assert result.risk_level == RiskLevel.NONE
        client.close()


class TestPatternLibrary:
    """Tests for the pattern library."""

    def test_get_common_patterns(self):
        """Test getting all common patterns."""
        patterns = get_common_patterns()
        assert len(patterns) >= 10

        # Check that key patterns exist
        pattern_names = [p.name for p in patterns]
        assert "advance_fee" in pattern_names
        assert "crypto_pump_dump" in pattern_names
        assert "fake_investment" in pattern_names
        assert "phishing" in pattern_names

    def test_pattern_validity(self):
        """Test that all patterns are valid."""
        patterns = get_common_patterns()

        for pattern in patterns:
            assert pattern.name, f"Pattern missing name: {pattern}"
            assert pattern.description, f"Pattern {pattern.name} missing description"
            assert pattern.severity in RiskLevel, f"Pattern {pattern.name} has invalid severity"

    def test_custom_pattern_creation(self):
        """Test creating a custom pattern."""
        custom = ScamPattern(
            name="my_custom_scam",
            description="A custom scam I've observed in my community",
            indicators=[
                "Uses specific jargon",
                "Targets elderly users",
            ],
            severity=RiskLevel.HIGH,
            examples=[
                "Example phrase 1",
                "Example phrase 2",
            ],
        )

        assert custom.name == "my_custom_scam"
        assert len(custom.indicators) == 2
        assert custom.severity == RiskLevel.HIGH

        # Can convert to prompt
        prompt = custom.to_prompt_section()
        assert "my_custom_scam" in prompt
        assert "custom scam" in prompt
