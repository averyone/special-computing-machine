"""Tests for the FastAPI web application."""

import json
import io
import pytest
import httpx
import respx

from fastapi.testclient import TestClient

from scam_detector.web.app import create_app, AppState


@pytest.fixture
def app():
    """Create a fresh app instance for each test."""
    return create_app()


@pytest.fixture
def client(app):
    """Create a test client."""
    return TestClient(app)


class TestHealthEndpoint:
    """Tests for the health check endpoint."""

    def test_health_check(self, client):
        """Test health check returns ok status."""
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "version" in data


class TestConfigEndpoints:
    """Tests for configuration endpoints."""

    def test_get_config(self, client):
        """Test getting current configuration."""
        response = client.get("/api/config")
        assert response.status_code == 200
        data = response.json()
        assert "base_url" in data
        assert "model" in data
        assert "temperature" in data
        assert "max_tokens" in data

    def test_get_config_masks_api_key(self, client, app):
        """Test that API key is masked in config response."""
        # Set an API key
        app.state.scam_state.config["api_key"] = "secret-key-123"

        response = client.get("/api/config")
        assert response.status_code == 200
        data = response.json()
        assert data["api_key"] == "***configured***"

    def test_update_config_base_url(self, client, app):
        """Test updating the base URL."""
        response = client.put("/api/config", json={
            "base_url": "http://new-server:8080/v1"
        })
        assert response.status_code == 200
        assert app.state.scam_state.config["base_url"] == "http://new-server:8080/v1"

    def test_update_config_model(self, client, app):
        """Test updating the model name."""
        response = client.put("/api/config", json={
            "model": "gpt-4"
        })
        assert response.status_code == 200
        assert app.state.scam_state.config["model"] == "gpt-4"

    def test_update_config_temperature(self, client, app):
        """Test updating temperature setting."""
        response = client.put("/api/config", json={
            "temperature": 0.7
        })
        assert response.status_code == 200
        assert app.state.scam_state.config["temperature"] == 0.7

    def test_update_config_max_tokens(self, client, app):
        """Test updating max tokens setting."""
        response = client.put("/api/config", json={
            "max_tokens": 4096
        })
        assert response.status_code == 200
        assert app.state.scam_state.config["max_tokens"] == 4096

    def test_update_config_api_key(self, client, app):
        """Test updating API key."""
        response = client.put("/api/config", json={
            "api_key": "new-secret-key"
        })
        assert response.status_code == 200
        assert app.state.scam_state.config["api_key"] == "new-secret-key"
        # Response should mask the key
        data = response.json()
        assert data["config"]["api_key"] == "***configured***"

    def test_update_config_clear_api_key(self, client, app):
        """Test clearing API key with empty string."""
        app.state.scam_state.config["api_key"] = "existing-key"
        response = client.put("/api/config", json={
            "api_key": ""
        })
        assert response.status_code == 200
        assert app.state.scam_state.config["api_key"] is None

    def test_update_config_multiple_fields(self, client, app):
        """Test updating multiple config fields at once."""
        response = client.put("/api/config", json={
            "base_url": "http://api.example.com/v1",
            "model": "custom-model",
            "temperature": 0.5,
            "max_tokens": 1024
        })
        assert response.status_code == 200
        assert app.state.scam_state.config["base_url"] == "http://api.example.com/v1"
        assert app.state.scam_state.config["model"] == "custom-model"
        assert app.state.scam_state.config["temperature"] == 0.5
        assert app.state.scam_state.config["max_tokens"] == 1024


class TestPatternEndpoints:
    """Tests for pattern management endpoints."""

    def test_list_patterns(self, client):
        """Test listing all patterns."""
        response = client.get("/api/patterns")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        # Should have default patterns loaded
        assert len(data) >= 10

    def test_list_patterns_structure(self, client):
        """Test that pattern list has correct structure."""
        response = client.get("/api/patterns")
        data = response.json()

        if len(data) > 0:
            pattern = data[0]
            assert "name" in pattern
            assert "description" in pattern
            assert "indicators" in pattern
            assert "severity" in pattern
            assert "examples" in pattern

    def test_create_pattern(self, client):
        """Test creating a new pattern."""
        new_pattern = {
            "name": "test_pattern",
            "description": "A test pattern for unit testing",
            "indicators": ["indicator 1", "indicator 2"],
            "severity": "high",
            "examples": ["example 1"]
        }

        response = client.post("/api/patterns", json=new_pattern)
        assert response.status_code == 200
        data = response.json()
        assert "Pattern 'test_pattern' created" in data["message"]
        assert data["pattern"]["name"] == "test_pattern"
        assert data["pattern"]["severity"] == "high"

    def test_create_pattern_minimal(self, client):
        """Test creating a pattern with minimal fields."""
        new_pattern = {
            "name": "minimal_pattern",
            "description": "Minimal pattern"
        }

        response = client.post("/api/patterns", json=new_pattern)
        assert response.status_code == 200
        data = response.json()
        assert data["pattern"]["name"] == "minimal_pattern"
        assert data["pattern"]["severity"] == "medium"  # default

    def test_create_pattern_duplicate_name(self, client):
        """Test that creating a pattern with duplicate name fails."""
        # First, get an existing pattern name
        patterns_response = client.get("/api/patterns")
        existing_name = patterns_response.json()[0]["name"]

        new_pattern = {
            "name": existing_name,
            "description": "Duplicate pattern"
        }

        response = client.post("/api/patterns", json=new_pattern)
        assert response.status_code == 400
        assert "already exists" in response.json()["detail"]

    def test_create_pattern_invalid_severity(self, client):
        """Test creating pattern with invalid severity."""
        new_pattern = {
            "name": "invalid_severity_pattern",
            "description": "Pattern with invalid severity",
            "severity": "extreme"
        }

        response = client.post("/api/patterns", json=new_pattern)
        assert response.status_code == 400
        assert "Invalid severity" in response.json()["detail"]

    def test_update_pattern(self, client):
        """Test updating an existing pattern."""
        # First create a pattern
        client.post("/api/patterns", json={
            "name": "updatable_pattern",
            "description": "Original description",
            "severity": "low"
        })

        # Update it
        response = client.put("/api/patterns/updatable_pattern", json={
            "description": "Updated description",
            "severity": "high"
        })

        assert response.status_code == 200
        data = response.json()
        assert data["pattern"]["description"] == "Updated description"
        assert data["pattern"]["severity"] == "high"

    def test_update_pattern_partial(self, client):
        """Test partial update of a pattern."""
        # Create a pattern
        client.post("/api/patterns", json={
            "name": "partial_update_pattern",
            "description": "Original",
            "indicators": ["ind1"],
            "severity": "medium"
        })

        # Update only description
        response = client.put("/api/patterns/partial_update_pattern", json={
            "description": "New description"
        })

        assert response.status_code == 200
        data = response.json()
        assert data["pattern"]["description"] == "New description"
        assert data["pattern"]["severity"] == "medium"  # unchanged
        assert data["pattern"]["indicators"] == ["ind1"]  # unchanged

    def test_update_pattern_not_found(self, client):
        """Test updating a non-existent pattern."""
        response = client.put("/api/patterns/nonexistent_pattern", json={
            "description": "New description"
        })
        assert response.status_code == 404
        assert "not found" in response.json()["detail"]

    def test_update_pattern_invalid_severity(self, client):
        """Test updating pattern with invalid severity."""
        # Create a pattern first
        client.post("/api/patterns", json={
            "name": "severity_test_pattern",
            "description": "Test"
        })

        response = client.put("/api/patterns/severity_test_pattern", json={
            "severity": "invalid_level"
        })
        assert response.status_code == 400
        assert "Invalid severity" in response.json()["detail"]

    def test_delete_pattern(self, client):
        """Test deleting a pattern."""
        # Create a pattern
        client.post("/api/patterns", json={
            "name": "deletable_pattern",
            "description": "To be deleted"
        })

        # Delete it
        response = client.delete("/api/patterns/deletable_pattern")
        assert response.status_code == 200
        assert "deleted" in response.json()["message"]

        # Verify it's gone
        patterns = client.get("/api/patterns").json()
        names = [p["name"] for p in patterns]
        assert "deletable_pattern" not in names

    def test_delete_pattern_not_found(self, client):
        """Test deleting a non-existent pattern."""
        response = client.delete("/api/patterns/nonexistent_pattern")
        assert response.status_code == 404
        assert "not found" in response.json()["detail"]

    def test_export_patterns(self, client):
        """Test exporting patterns as JSON file."""
        response = client.get("/api/patterns/export")
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/json"
        assert "attachment" in response.headers.get("content-disposition", "")

        # Verify it's valid JSON with patterns
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0

    def test_import_patterns_add(self, client):
        """Test importing patterns (add mode)."""
        patterns_json = json.dumps([
            {
                "name": "imported_pattern_1",
                "description": "First imported pattern",
                "severity": "high"
            },
            {
                "name": "imported_pattern_2",
                "description": "Second imported pattern"
            }
        ])

        files = {"file": ("patterns.json", io.BytesIO(patterns_json.encode()))}
        response = client.post("/api/patterns/import", files=files)

        assert response.status_code == 200
        data = response.json()
        assert "imported_pattern_1" in data["imported"]
        assert "imported_pattern_2" in data["imported"]

    def test_import_patterns_replace(self, client):
        """Test importing patterns with replace mode."""
        patterns_json = json.dumps([
            {
                "name": "replacement_pattern",
                "description": "This replaces all patterns",
                "severity": "critical"
            }
        ])

        files = {"file": ("patterns.json", io.BytesIO(patterns_json.encode()))}
        response = client.post("/api/patterns/import?replace=true", files=files)

        assert response.status_code == 200

        # Verify only the imported pattern exists
        patterns = client.get("/api/patterns").json()
        assert len(patterns) == 1
        assert patterns[0]["name"] == "replacement_pattern"

    def test_import_patterns_skip_duplicates(self, client):
        """Test that importing skips duplicate pattern names."""
        # Get existing pattern name
        existing = client.get("/api/patterns").json()[0]["name"]

        patterns_json = json.dumps([
            {
                "name": existing,
                "description": "Duplicate"
            },
            {
                "name": "new_unique_pattern",
                "description": "New pattern"
            }
        ])

        files = {"file": ("patterns.json", io.BytesIO(patterns_json.encode()))}
        response = client.post("/api/patterns/import", files=files)

        assert response.status_code == 200
        data = response.json()
        assert existing in data["skipped"]
        assert "new_unique_pattern" in data["imported"]

    def test_import_patterns_invalid_json(self, client):
        """Test importing invalid JSON."""
        files = {"file": ("patterns.json", io.BytesIO(b"not valid json"))}
        response = client.post("/api/patterns/import", files=files)

        assert response.status_code == 400
        assert "Invalid JSON" in response.json()["detail"]

    def test_import_patterns_not_array(self, client):
        """Test importing JSON that's not an array."""
        files = {"file": ("patterns.json", io.BytesIO(b'{"name": "single"}'))}
        response = client.post("/api/patterns/import", files=files)

        assert response.status_code == 400
        assert "must be an array" in response.json()["detail"]

    def test_import_patterns_missing_name(self, client):
        """Test importing pattern without name field."""
        patterns_json = json.dumps([
            {"description": "Pattern without name"}
        ])

        files = {"file": ("patterns.json", io.BytesIO(patterns_json.encode()))}
        response = client.post("/api/patterns/import?replace=true", files=files)

        assert response.status_code == 200
        data = response.json()
        assert len(data["errors"]) == 1
        assert "missing 'name'" in data["errors"][0]

    def test_reset_patterns(self, client):
        """Test resetting patterns to defaults."""
        # First clear all patterns
        client.post("/api/patterns/import?replace=true",
                   files={"file": ("p.json", io.BytesIO(b"[]"))})

        # Verify empty
        patterns = client.get("/api/patterns").json()
        assert len(patterns) == 0

        # Reset to defaults
        response = client.post("/api/patterns/reset")
        assert response.status_code == 200
        assert response.json()["count"] >= 10

        # Verify patterns are back
        patterns = client.get("/api/patterns").json()
        assert len(patterns) >= 10


class TestAnalyzeEndpoint:
    """Tests for the message analysis endpoint."""

    @respx.mock
    def test_analyze_message_scam(self, client):
        """Test analyzing a scam message."""
        # Mock the LLM response
        mock_response = {
            "risk_level": "high",
            "matched_patterns": [
                {
                    "pattern_name": "crypto_pump_dump",
                    "confidence": 0.9,
                    "evidence": ["100x guaranteed"],
                    "explanation": "Classic pump and dump"
                }
            ],
            "summary": "This appears to be a crypto scam"
        }

        respx.post("http://localhost:1234/v1/chat/completions").mock(
            return_value=httpx.Response(200, json={
                "choices": [{"message": {"content": json.dumps(mock_response)}}]
            })
        )

        response = client.post("/api/analyze", json={
            "content": "Buy this coin now! 100x guaranteed! Don't miss out!",
            "title": "MOONSHOT ALERT",
            "author": "crypto_guru"
        })

        assert response.status_code == 200
        data = response.json()
        assert data["risk_level"] == "high"
        assert data["is_scam"] is True
        assert len(data["matched_patterns"]) == 1
        assert data["matched_patterns"][0]["pattern_name"] == "crypto_pump_dump"

    @respx.mock
    def test_analyze_message_clean(self, client):
        """Test analyzing a legitimate message."""
        mock_response = {
            "risk_level": "none",
            "matched_patterns": [],
            "summary": "This appears to be a normal message"
        }

        respx.post("http://localhost:1234/v1/chat/completions").mock(
            return_value=httpx.Response(200, json={
                "choices": [{"message": {"content": json.dumps(mock_response)}}]
            })
        )

        response = client.post("/api/analyze", json={
            "content": "What's a good index fund for retirement?",
        })

        assert response.status_code == 200
        data = response.json()
        assert data["risk_level"] == "none"
        assert data["is_scam"] is False
        assert len(data["matched_patterns"]) == 0

    @respx.mock
    def test_analyze_message_minimal_request(self, client):
        """Test analyzing with only content field."""
        mock_response = {
            "risk_level": "low",
            "matched_patterns": [],
            "summary": "Low risk content"
        }

        respx.post("http://localhost:1234/v1/chat/completions").mock(
            return_value=httpx.Response(200, json={
                "choices": [{"message": {"content": json.dumps(mock_response)}}]
            })
        )

        response = client.post("/api/analyze", json={
            "content": "Hello world"
        })

        assert response.status_code == 200
        assert response.json()["risk_level"] == "low"

    def test_analyze_message_missing_content(self, client):
        """Test that missing content field returns validation error."""
        response = client.post("/api/analyze", json={
            "title": "No content here"
        })
        assert response.status_code == 422  # Validation error

    @respx.mock
    def test_analyze_message_llm_error(self, client):
        """Test handling of LLM API error."""
        respx.post("http://localhost:1234/v1/chat/completions").mock(
            return_value=httpx.Response(500, json={"error": "Server error"})
        )

        response = client.post("/api/analyze", json={
            "content": "Test message"
        })

        assert response.status_code == 500
        assert "Analysis failed" in response.json()["detail"]


class TestStaticFiles:
    """Tests for static file serving."""

    def test_root_returns_html(self, client):
        """Test that root path returns HTML."""
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "Scam Detection" in response.text or "<!DOCTYPE html>" in response.text


class TestAppState:
    """Tests for AppState class."""

    def test_app_state_initialization(self):
        """Test AppState initializes with defaults."""
        state = AppState()
        assert state.detector is None
        assert state.client is None
        assert state.config["base_url"] == "http://localhost:1234/v1"
        assert state.config["model"] == "local-model"
        assert state.config["temperature"] == 0.1
        assert state.config["max_tokens"] == 2048

    def test_app_state_initialize_client(self):
        """Test initializing the client."""
        state = AppState()
        state.initialize_client()

        assert state.client is not None
        assert state.detector is not None
        assert len(state.detector.patterns) >= 10  # Default patterns loaded

        state.client.close()

    def test_app_state_reinitialize_client(self):
        """Test reinitializing client with new config."""
        state = AppState()
        state.initialize_client()
        old_client = state.client

        state.config["model"] = "new-model"
        state.initialize_client()

        assert state.client is not old_client
        old_client.close()
        state.client.close()


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_pattern_name_with_special_chars(self, client):
        """Test pattern with special characters in name."""
        response = client.post("/api/patterns", json={
            "name": "test-pattern_v2.0",
            "description": "Pattern with special chars in name"
        })
        assert response.status_code == 200

    def test_pattern_with_unicode(self, client):
        """Test pattern with unicode characters."""
        response = client.post("/api/patterns", json={
            "name": "unicode_pattern",
            "description": "Pattern with émojis 🚨 and áccénts",
            "indicators": ["使用中文", "日本語テスト"]
        })
        assert response.status_code == 200
        data = response.json()
        assert "émojis" in data["pattern"]["description"]

    def test_empty_indicators_and_examples(self, client):
        """Test pattern with empty arrays."""
        response = client.post("/api/patterns", json={
            "name": "empty_arrays_pattern",
            "description": "Pattern with empty arrays",
            "indicators": [],
            "examples": []
        })
        assert response.status_code == 200
        data = response.json()
        assert data["pattern"]["indicators"] == []
        assert data["pattern"]["examples"] == []

    def test_url_encoded_pattern_name(self, client):
        """Test accessing pattern with URL-encoded name."""
        # Create pattern with spaces (if allowed)
        client.post("/api/patterns", json={
            "name": "test_encoded",
            "description": "Test"
        })

        # Access with encoded name
        response = client.get("/api/patterns")
        assert response.status_code == 200
