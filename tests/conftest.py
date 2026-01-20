"""Test configuration and fixtures for Shadow-API Mapper."""

import pytest
from pathlib import Path
import tempfile

from shadow_mapper.core.config import Settings
from shadow_mapper.core.models import Endpoint, HTTPMethod, SourceLocation


@pytest.fixture
def settings() -> Settings:
    """Default settings for testing."""
    return Settings()


@pytest.fixture
def temp_dir() -> Path:
    """Temporary directory for test outputs."""
    with tempfile.TemporaryDirectory() as tmp:
        yield Path(tmp)


@pytest.fixture
def sample_js_file(temp_dir: Path) -> Path:
    """Create a sample JavaScript file with API calls."""
    js_content = '''
const API_BASE = "https://api.example.com";
const USER_ENDPOINT = "/api/v1/users";

async function fetchUsers() {
    const response = await fetch(API_BASE + USER_ENDPOINT);
    return response.json();
}

async function createUser(data) {
    return axios.post("/api/v1/users", data);
}

// Admin endpoints
const ADMIN_SECRET = "sk_live_1234567890abcdef";
fetch("/api/admin/dashboard");

// Legacy endpoint
fetch("/api/v0/legacy/auth");
'''
    
    file_path = temp_dir / "app.js"
    file_path.write_text(js_content)
    return file_path


@pytest.fixture
def sample_openapi_spec(temp_dir: Path) -> Path:
    """Create a sample OpenAPI specification."""
    import yaml
    
    spec = {
        "openapi": "3.0.3",
        "info": {
            "title": "Test API",
            "version": "1.0.0",
        },
        "paths": {
            "/api/v1/users": {
                "get": {
                    "summary": "List users",
                    "responses": {"200": {"description": "OK"}},
                },
                "post": {
                    "summary": "Create user",
                    "responses": {"201": {"description": "Created"}},
                },
            },
            "/api/v1/products": {
                "get": {
                    "summary": "List products",
                    "responses": {"200": {"description": "OK"}},
                },
            },
            "/api/v0/legacy/auth": {
                "post": {
                    "summary": "Legacy auth",
                    "deprecated": True,
                    "responses": {"200": {"description": "OK"}},
                },
            },
        },
    }
    
    spec_path = temp_dir / "openapi.yaml"
    with open(spec_path, "w") as f:
        yaml.dump(spec, f)
    
    return spec_path


@pytest.fixture
def sample_endpoints() -> list[Endpoint]:
    """Sample endpoints for testing."""
    return [
        Endpoint(
            url="/api/v1/users",
            method=HTTPMethod.GET,
            source=SourceLocation(file=Path("app.js"), line=10),
        ),
        Endpoint(
            url="/api/v1/users",
            method=HTTPMethod.POST,
            source=SourceLocation(file=Path("app.js"), line=15),
        ),
        Endpoint(
            url="/api/admin/dashboard",
            method=HTTPMethod.GET,
            source=SourceLocation(file=Path("app.js"), line=20),
        ),
        Endpoint(
            url="/api/v0/legacy/auth",
            method=HTTPMethod.POST,
            source=SourceLocation(file=Path("app.js"), line=25),
        ),
    ]
