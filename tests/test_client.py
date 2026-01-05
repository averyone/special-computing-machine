"""Tests for the OpenAI-compatible client."""

import json
import pytest
import httpx
import respx

from scam_detector.client import OpenAIClient, ChatMessage, ClientConfig


class TestClientConfig:
    """Tests for ClientConfig."""

    def test_defaults(self):
        """Test default configuration values."""
        config = ClientConfig()
        assert config.base_url == "http://localhost:1234/v1"
        assert config.api_key is None
        assert config.model == "local-model"
        assert config.timeout == 120.0
        assert config.max_tokens == 2048
        assert config.temperature == 0.1


class TestChatMessage:
    """Tests for ChatMessage."""

    def test_creation(self):
        """Test creating a chat message."""
        msg = ChatMessage(role="user", content="Hello")
        assert msg.role == "user"
        assert msg.content == "Hello"


class TestOpenAIClient:
    """Tests for OpenAIClient."""

    def test_initialization(self):
        """Test client initialization."""
        client = OpenAIClient(
            base_url="http://localhost:8000/v1",
            api_key="test-key",
            model="test-model",
        )
        assert client.config.base_url == "http://localhost:8000/v1"
        assert client.config.api_key == "test-key"
        assert client.config.model == "test-model"
        client.close()

    def test_url_trailing_slash_removal(self):
        """Test that trailing slashes are removed from base URL."""
        client = OpenAIClient(base_url="http://localhost:1234/v1/")
        assert client.config.base_url == "http://localhost:1234/v1"
        client.close()

    def test_headers_without_api_key(self):
        """Test headers when no API key is provided."""
        client = OpenAIClient()
        headers = client._get_headers()
        assert "Authorization" not in headers
        assert headers["Content-Type"] == "application/json"
        client.close()

    def test_headers_with_api_key(self):
        """Test headers when API key is provided."""
        client = OpenAIClient(api_key="test-key")
        headers = client._get_headers()
        assert headers["Authorization"] == "Bearer test-key"
        client.close()

    def test_build_request_body(self):
        """Test building request body."""
        client = OpenAIClient(model="test-model", max_tokens=100, temperature=0.5)
        messages = [
            ChatMessage(role="system", content="You are helpful"),
            ChatMessage(role="user", content="Hello"),
        ]
        body = client._build_request_body(messages)

        assert body["model"] == "test-model"
        assert body["max_tokens"] == 100
        assert body["temperature"] == 0.5
        assert len(body["messages"]) == 2
        assert body["messages"][0]["role"] == "system"
        assert body["messages"][1]["content"] == "Hello"
        client.close()

    def test_extract_content(self):
        """Test extracting content from response."""
        client = OpenAIClient()
        response = {
            "choices": [
                {"message": {"content": "Hello there!"}}
            ]
        }
        content = client._extract_content(response)
        assert content == "Hello there!"
        client.close()

    def test_extract_content_empty_choices(self):
        """Test error on empty choices."""
        client = OpenAIClient()
        with pytest.raises(ValueError, match="No choices"):
            client._extract_content({"choices": []})
        client.close()

    def test_parse_json_response_direct(self):
        """Test parsing direct JSON response."""
        client = OpenAIClient()
        content = '{"key": "value"}'
        result = client._parse_json_response(content)
        assert result == {"key": "value"}
        client.close()

    def test_parse_json_response_markdown_block(self):
        """Test parsing JSON from markdown code block."""
        client = OpenAIClient()
        content = '''Here's the result:
```json
{"key": "value"}
```
That's all!'''
        result = client._parse_json_response(content)
        assert result == {"key": "value"}
        client.close()

    def test_parse_json_response_embedded(self):
        """Test parsing embedded JSON."""
        client = OpenAIClient()
        content = 'The result is {"key": "value"} as shown.'
        result = client._parse_json_response(content)
        assert result == {"key": "value"}
        client.close()

    def test_parse_json_response_failure(self):
        """Test failure when no valid JSON."""
        client = OpenAIClient()
        with pytest.raises(json.JSONDecodeError):
            client._parse_json_response("No JSON here")
        client.close()

    @respx.mock
    def test_chat_sync(self):
        """Test synchronous chat completion."""
        respx.post("http://localhost:1234/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={
                    "choices": [
                        {"message": {"content": "Hello back!"}}
                    ]
                },
            )
        )

        client = OpenAIClient()
        messages = [ChatMessage(role="user", content="Hello")]
        response = client.chat(messages)

        assert response == "Hello back!"
        client.close()

    @respx.mock
    def test_chat_json_sync(self):
        """Test synchronous chat with JSON response."""
        respx.post("http://localhost:1234/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={
                    "choices": [
                        {"message": {"content": '{"result": "success"}'}}
                    ]
                },
            )
        )

        client = OpenAIClient()
        messages = [ChatMessage(role="user", content="Hello")]
        response = client.chat_json(messages)

        assert response == {"result": "success"}
        client.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_chat_async(self):
        """Test asynchronous chat completion."""
        respx.post("http://localhost:1234/v1/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={
                    "choices": [
                        {"message": {"content": "Async hello!"}}
                    ]
                },
            )
        )

        async with OpenAIClient() as client:
            messages = [ChatMessage(role="user", content="Hello")]
            response = await client.achat(messages)
            assert response == "Async hello!"

    def test_context_manager_sync(self):
        """Test sync context manager."""
        with OpenAIClient() as client:
            assert client._sync_client is None  # Lazy initialization

    @pytest.mark.asyncio
    async def test_context_manager_async(self):
        """Test async context manager."""
        async with OpenAIClient() as client:
            assert client._async_client is None  # Lazy initialization
