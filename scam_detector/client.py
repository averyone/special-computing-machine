"""OpenAI-compatible API client for LLM inference.

This client works with any OpenAI-compatible API endpoint, including:
- OpenAI's official API
- LM Studio's local server
- Ollama with OpenAI compatibility
- vLLM, text-generation-inference, and other compatible servers
"""

import json
from typing import Optional
from dataclasses import dataclass, field

import httpx


@dataclass
class ChatMessage:
    """A chat message for the conversation."""

    role: str  # "system", "user", or "assistant"
    content: str


@dataclass
class ClientConfig:
    """Configuration for the OpenAI-compatible client."""

    base_url: str = "http://localhost:1234/v1"
    api_key: Optional[str] = None
    model: str = "local-model"
    timeout: float = 120.0
    max_tokens: int = 2048
    temperature: float = 0.1
    default_headers: dict = field(default_factory=dict)


class OpenAIClient:
    """Client for OpenAI-compatible APIs.

    Supports both synchronous and asynchronous operations.
    Works with LM Studio, Ollama, vLLM, and other compatible servers.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:1234/v1",
        api_key: Optional[str] = None,
        model: str = "local-model",
        timeout: float = 120.0,
        max_tokens: int = 2048,
        temperature: float = 0.1,
    ):
        """Initialize the OpenAI-compatible client.

        Args:
            base_url: Base URL for the API (e.g., "http://localhost:1234/v1")
            api_key: API key (optional for local servers)
            model: Model identifier to use
            timeout: Request timeout in seconds
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature (lower = more deterministic)
        """
        self.config = ClientConfig(
            base_url=base_url.rstrip("/"),
            api_key=api_key,
            model=model,
            timeout=timeout,
            max_tokens=max_tokens,
            temperature=temperature,
        )
        self._sync_client: Optional[httpx.Client] = None
        self._async_client: Optional[httpx.AsyncClient] = None

    def _get_headers(self) -> dict:
        """Get request headers including authorization."""
        headers = {
            "Content-Type": "application/json",
            **self.config.default_headers,
        }
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        return headers

    def _get_sync_client(self) -> httpx.Client:
        """Get or create synchronous HTTP client."""
        if self._sync_client is None:
            self._sync_client = httpx.Client(
                timeout=self.config.timeout,
                headers=self._get_headers(),
            )
        return self._sync_client

    async def _get_async_client(self) -> httpx.AsyncClient:
        """Get or create asynchronous HTTP client."""
        if self._async_client is None:
            self._async_client = httpx.AsyncClient(
                timeout=self.config.timeout,
                headers=self._get_headers(),
            )
        return self._async_client

    def _build_request_body(
        self,
        messages: list[ChatMessage],
        **kwargs,
    ) -> dict:
        """Build the request body for chat completion."""
        return {
            "model": kwargs.get("model", self.config.model),
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
            "temperature": kwargs.get("temperature", self.config.temperature),
            **{k: v for k, v in kwargs.items()
               if k not in ("model", "max_tokens", "temperature")},
        }

    def chat(
        self,
        messages: list[ChatMessage],
        **kwargs,
    ) -> str:
        """Send a synchronous chat completion request.

        Args:
            messages: List of chat messages
            **kwargs: Additional parameters to pass to the API

        Returns:
            The assistant's response content

        Raises:
            httpx.HTTPError: If the request fails
            ValueError: If the response format is unexpected
        """
        client = self._get_sync_client()
        url = f"{self.config.base_url}/chat/completions"
        body = self._build_request_body(messages, **kwargs)

        response = client.post(url, json=body)
        response.raise_for_status()

        data = response.json()
        return self._extract_content(data)

    async def achat(
        self,
        messages: list[ChatMessage],
        **kwargs,
    ) -> str:
        """Send an asynchronous chat completion request.

        Args:
            messages: List of chat messages
            **kwargs: Additional parameters to pass to the API

        Returns:
            The assistant's response content

        Raises:
            httpx.HTTPError: If the request fails
            ValueError: If the response format is unexpected
        """
        client = await self._get_async_client()
        url = f"{self.config.base_url}/chat/completions"
        body = self._build_request_body(messages, **kwargs)

        response = await client.post(url, json=body)
        response.raise_for_status()

        data = response.json()
        return self._extract_content(data)

    def _extract_content(self, response_data: dict) -> str:
        """Extract the content from an API response."""
        try:
            choices = response_data.get("choices", [])
            if not choices:
                raise ValueError("No choices in response")

            message = choices[0].get("message", {})
            content = message.get("content", "")

            if content is None:
                content = ""

            return content
        except (KeyError, IndexError, TypeError) as e:
            raise ValueError(f"Unexpected response format: {e}") from e

    def chat_json(
        self,
        messages: list[ChatMessage],
        **kwargs,
    ) -> dict:
        """Send a chat request expecting JSON response.

        Attempts to parse the response as JSON. If the response contains
        markdown code blocks, extracts JSON from within them.

        Args:
            messages: List of chat messages
            **kwargs: Additional parameters to pass to the API

        Returns:
            Parsed JSON response as a dictionary

        Raises:
            json.JSONDecodeError: If response is not valid JSON
        """
        content = self.chat(messages, **kwargs)
        return self._parse_json_response(content)

    async def achat_json(
        self,
        messages: list[ChatMessage],
        **kwargs,
    ) -> dict:
        """Send an async chat request expecting JSON response.

        Args:
            messages: List of chat messages
            **kwargs: Additional parameters to pass to the API

        Returns:
            Parsed JSON response as a dictionary

        Raises:
            json.JSONDecodeError: If response is not valid JSON
        """
        content = await self.achat(messages, **kwargs)
        return self._parse_json_response(content)

    def _parse_json_response(self, content: str) -> dict:
        """Parse JSON from response content, handling markdown code blocks."""
        content = content.strip()

        # Try direct JSON parse first
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass

        # Try to extract JSON from markdown code blocks
        if "```" in content:
            # Find JSON block
            import re
            patterns = [
                r"```json\s*([\s\S]*?)```",
                r"```\s*([\s\S]*?)```",
            ]
            for pattern in patterns:
                match = re.search(pattern, content)
                if match:
                    try:
                        return json.loads(match.group(1).strip())
                    except json.JSONDecodeError:
                        continue

        # Try to find JSON object or array in content
        for start_char, end_char in [("{", "}"), ("[", "]")]:
            start_idx = content.find(start_char)
            end_idx = content.rfind(end_char)
            if start_idx != -1 and end_idx > start_idx:
                try:
                    return json.loads(content[start_idx:end_idx + 1])
                except json.JSONDecodeError:
                    continue

        # Give up
        raise json.JSONDecodeError(
            f"Could not parse JSON from response",
            content,
            0,
        )

    def close(self):
        """Close synchronous client connections."""
        if self._sync_client:
            self._sync_client.close()
            self._sync_client = None

    async def aclose(self):
        """Close asynchronous client connections."""
        if self._async_client:
            await self._async_client.aclose()
            self._async_client = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.aclose()
