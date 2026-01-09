"""FastAPI web application for scam detection."""

import json
from typing import Optional
from pathlib import Path

from fastapi import FastAPI, HTTPException, UploadFile, File, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from ..models import ScamPattern, Post, RiskLevel, DetectionResult
from ..detector import ScamDetector
from ..client import OpenAIClient
from ..patterns import get_common_patterns


# Request/Response models for the API
class AnalyzeRequest(BaseModel):
    """Request to analyze a message for scams."""
    content: str
    title: Optional[str] = None
    author: Optional[str] = None


class PatternCreate(BaseModel):
    """Request to create a new scam pattern."""
    name: str
    description: str
    indicators: list[str] = []
    severity: str = "medium"
    examples: list[str] = []


class PatternUpdate(BaseModel):
    """Request to update an existing pattern."""
    description: Optional[str] = None
    indicators: Optional[list[str]] = None
    severity: Optional[str] = None
    examples: Optional[list[str]] = None


class ConfigUpdate(BaseModel):
    """Request to update LLM configuration."""
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    model: Optional[str] = None
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None


class AppState:
    """Application state container."""

    def __init__(self):
        self.detector: Optional[ScamDetector] = None
        self.client: Optional[OpenAIClient] = None
        self.config = {
            "base_url": "http://localhost:1234/v1",
            "api_key": None,
            "model": "local-model",
            "temperature": 0.1,
            "max_tokens": 2048,
        }

    def initialize_client(self):
        """Initialize or reinitialize the OpenAI client."""
        self.client = OpenAIClient(
            base_url=self.config["base_url"],
            api_key=self.config["api_key"],
            model=self.config["model"],
            temperature=self.config["temperature"],
            max_tokens=self.config["max_tokens"],
        )
        self.detector = ScamDetector(client=self.client)
        # Load common patterns by default
        self.detector.add_patterns(get_common_patterns())


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""

    app = FastAPI(
        title="Scam Detection System",
        description="AI-powered scam pattern detection for messages and posts",
        version="0.1.0",
    )

    # Application state
    state = AppState()
    state.initialize_client()

    # Store state on app for access in routes
    app.state.scam_state = state

    # API Routes

    @app.get("/", response_class=HTMLResponse)
    async def root():
        """Serve the main web interface."""
        static_dir = Path(__file__).parent / "static"
        index_path = static_dir / "index.html"
        if index_path.exists():
            return HTMLResponse(content=index_path.read_text())
        return HTMLResponse(content="<h1>Scam Detection System</h1><p>Static files not found.</p>")

    @app.get("/api/health")
    async def health_check():
        """Health check endpoint."""
        return {"status": "ok", "version": "0.1.0"}

    @app.get("/api/config")
    async def get_config():
        """Get current LLM configuration."""
        config = state.config.copy()
        # Don't expose API key
        if config.get("api_key"):
            config["api_key"] = "***configured***"
        return config

    @app.put("/api/config")
    async def update_config(update: ConfigUpdate):
        """Update LLM configuration."""
        if update.base_url is not None:
            state.config["base_url"] = update.base_url
        if update.api_key is not None:
            state.config["api_key"] = update.api_key if update.api_key else None
        if update.model is not None:
            state.config["model"] = update.model
        if update.temperature is not None:
            state.config["temperature"] = update.temperature
        if update.max_tokens is not None:
            state.config["max_tokens"] = update.max_tokens

        # Reinitialize client with new config
        state.initialize_client()

        config = state.config.copy()
        if config.get("api_key"):
            config["api_key"] = "***configured***"
        return {"message": "Configuration updated", "config": config}

    @app.post("/api/analyze")
    async def analyze_message(request: AnalyzeRequest):
        """Analyze a message for scam patterns."""
        if not state.detector:
            raise HTTPException(status_code=500, detail="Detector not initialized")

        post = Post(
            content=request.content,
            title=request.title,
            author=request.author,
        )

        try:
            result = await state.detector.aanalyze(post)
            return {
                "risk_level": result.risk_level.value,
                "is_scam": result.is_scam,
                "matched_patterns": [
                    {
                        "pattern_name": m.pattern_name,
                        "confidence": m.confidence,
                        "evidence": m.evidence,
                        "explanation": m.explanation,
                    }
                    for m in result.matched_patterns
                ],
                "summary": result.summary,
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

    @app.get("/api/patterns")
    async def list_patterns():
        """List all configured scam patterns."""
        if not state.detector:
            raise HTTPException(status_code=500, detail="Detector not initialized")

        return [
            {
                "name": p.name,
                "description": p.description,
                "indicators": p.indicators,
                "severity": p.severity.value,
                "examples": p.examples,
            }
            for p in state.detector.patterns
        ]

    @app.post("/api/patterns")
    async def create_pattern(pattern: PatternCreate):
        """Add a new scam pattern."""
        if not state.detector:
            raise HTTPException(status_code=500, detail="Detector not initialized")

        # Check if pattern with this name already exists
        existing_names = [p.name for p in state.detector.patterns]
        if pattern.name in existing_names:
            raise HTTPException(status_code=400, detail=f"Pattern '{pattern.name}' already exists")

        try:
            severity = RiskLevel(pattern.severity.lower())
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid severity: {pattern.severity}")

        new_pattern = ScamPattern(
            name=pattern.name,
            description=pattern.description,
            indicators=pattern.indicators,
            severity=severity,
            examples=pattern.examples,
        )

        state.detector.add_pattern(new_pattern)

        return {
            "message": f"Pattern '{pattern.name}' created",
            "pattern": {
                "name": new_pattern.name,
                "description": new_pattern.description,
                "indicators": new_pattern.indicators,
                "severity": new_pattern.severity.value,
                "examples": new_pattern.examples,
            }
        }

    @app.put("/api/patterns/{pattern_name}")
    async def update_pattern(pattern_name: str, update: PatternUpdate):
        """Update an existing scam pattern."""
        if not state.detector:
            raise HTTPException(status_code=500, detail="Detector not initialized")

        # Find the pattern
        pattern_idx = None
        for i, p in enumerate(state.detector.patterns):
            if p.name == pattern_name:
                pattern_idx = i
                break

        if pattern_idx is None:
            raise HTTPException(status_code=404, detail=f"Pattern '{pattern_name}' not found")

        existing = state.detector.patterns[pattern_idx]

        # Build updated pattern
        severity = existing.severity
        if update.severity is not None:
            try:
                severity = RiskLevel(update.severity.lower())
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid severity: {update.severity}")

        updated = ScamPattern(
            name=pattern_name,
            description=update.description if update.description is not None else existing.description,
            indicators=update.indicators if update.indicators is not None else existing.indicators,
            severity=severity,
            examples=update.examples if update.examples is not None else existing.examples,
        )

        state.detector.patterns[pattern_idx] = updated

        return {
            "message": f"Pattern '{pattern_name}' updated",
            "pattern": {
                "name": updated.name,
                "description": updated.description,
                "indicators": updated.indicators,
                "severity": updated.severity.value,
                "examples": updated.examples,
            }
        }

    @app.delete("/api/patterns/{pattern_name}")
    async def delete_pattern(pattern_name: str):
        """Delete a scam pattern."""
        if not state.detector:
            raise HTTPException(status_code=500, detail="Detector not initialized")

        if state.detector.remove_pattern(pattern_name):
            return {"message": f"Pattern '{pattern_name}' deleted"}
        else:
            raise HTTPException(status_code=404, detail=f"Pattern '{pattern_name}' not found")

    @app.get("/api/patterns/export")
    async def export_patterns():
        """Export all patterns as a downloadable JSON file."""
        if not state.detector:
            raise HTTPException(status_code=500, detail="Detector not initialized")

        patterns_data = [
            {
                "name": p.name,
                "description": p.description,
                "indicators": p.indicators,
                "severity": p.severity.value,
                "examples": p.examples,
            }
            for p in state.detector.patterns
        ]

        json_content = json.dumps(patterns_data, indent=2)

        return Response(
            content=json_content,
            media_type="application/json",
            headers={
                "Content-Disposition": "attachment; filename=scam_patterns.json"
            }
        )

    @app.post("/api/patterns/import")
    async def import_patterns(file: UploadFile = File(...), replace: bool = False):
        """Import patterns from a JSON file."""
        if not state.detector:
            raise HTTPException(status_code=500, detail="Detector not initialized")

        try:
            content = await file.read()
            patterns_data = json.loads(content.decode("utf-8"))
        except json.JSONDecodeError as e:
            raise HTTPException(status_code=400, detail=f"Invalid JSON: {str(e)}")
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to read file: {str(e)}")

        if not isinstance(patterns_data, list):
            raise HTTPException(status_code=400, detail="JSON must be an array of patterns")

        if replace:
            state.detector.clear_patterns()

        imported = []
        skipped = []
        errors = []

        existing_names = {p.name for p in state.detector.patterns}

        for i, p_data in enumerate(patterns_data):
            try:
                if not isinstance(p_data, dict):
                    errors.append(f"Item {i}: not an object")
                    continue

                name = p_data.get("name")
                if not name:
                    errors.append(f"Item {i}: missing 'name'")
                    continue

                if name in existing_names and not replace:
                    skipped.append(name)
                    continue

                severity = RiskLevel.MEDIUM
                if "severity" in p_data:
                    try:
                        severity = RiskLevel(p_data["severity"].lower())
                    except ValueError:
                        severity = RiskLevel.MEDIUM

                pattern = ScamPattern(
                    name=name,
                    description=p_data.get("description", ""),
                    indicators=p_data.get("indicators", []),
                    severity=severity,
                    examples=p_data.get("examples", []),
                )

                state.detector.add_pattern(pattern)
                existing_names.add(name)
                imported.append(name)

            except Exception as e:
                errors.append(f"Item {i} ({p_data.get('name', 'unknown')}): {str(e)}")

        return {
            "message": f"Import complete: {len(imported)} imported, {len(skipped)} skipped, {len(errors)} errors",
            "imported": imported,
            "skipped": skipped,
            "errors": errors,
        }

    @app.post("/api/patterns/reset")
    async def reset_patterns():
        """Reset patterns to the default set."""
        if not state.detector:
            raise HTTPException(status_code=500, detail="Detector not initialized")

        state.detector.clear_patterns()
        state.detector.add_patterns(get_common_patterns())

        return {"message": "Patterns reset to defaults", "count": len(state.detector.patterns)}

    # Mount static files last (so API routes take precedence)
    static_dir = Path(__file__).parent / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    return app


# Create default app instance
app = create_app()
