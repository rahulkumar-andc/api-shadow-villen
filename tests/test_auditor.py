"""Tests for the Auditor module."""

import pytest
from pathlib import Path

from shadow_mapper.core.config import Settings
from shadow_mapper.core.models import Endpoint, EndpointStatus, HTTPMethod
from shadow_mapper.auditor import AuditEngine, SpecParser, SpecGenerator
from shadow_mapper.auditor.sarif import SARIFGenerator


class TestSpecParser:
    """Tests for OpenAPI specification parsing."""
    
    def test_parse_openapi3(self, sample_openapi_spec: Path):
        """Test parsing OpenAPI 3.x specification."""
        parser = SpecParser()
        endpoints = parser.parse(sample_openapi_spec)
        
        assert len(endpoints) >= 4
        
        # Check specific endpoints
        paths = [(ep.path, ep.method.value) for ep in endpoints]
        assert ("/api/v1/users", "GET") in paths
        assert ("/api/v1/users", "POST") in paths
        assert ("/api/v1/products", "GET") in paths
    
    def test_deprecated_endpoint(self, sample_openapi_spec: Path):
        """Test detection of deprecated endpoints."""
        parser = SpecParser()
        endpoints = parser.parse(sample_openapi_spec)
        
        deprecated = [ep for ep in endpoints if ep.deprecated]
        assert len(deprecated) >= 1
        assert any("/legacy/" in ep.path for ep in deprecated)


class TestAuditEngine:
    """Tests for the audit engine."""
    
    def test_compare_finds_shadow_apis(
        self,
        settings: Settings,
        sample_endpoints: list[Endpoint],
        sample_openapi_spec: Path,
    ):
        """Test that undocumented endpoints are marked as Shadow."""
        engine = AuditEngine(settings)
        result = engine.compare(sample_endpoints, sample_openapi_spec)
        
        # /api/admin/dashboard should be Shadow (not in spec)
        assert len(result.shadow) >= 1
        shadow_urls = [ep.url for ep in result.shadow]
        assert "/api/admin/dashboard" in shadow_urls
    
    def test_compare_finds_documented(
        self,
        settings: Settings,
        sample_endpoints: list[Endpoint],
        sample_openapi_spec: Path,
    ):
        """Test that documented endpoints are correctly identified."""
        engine = AuditEngine(settings)
        result = engine.compare(sample_endpoints, sample_openapi_spec)
        
        # /api/v1/users GET and POST should be documented
        assert len(result.documented) >= 2
    
    def test_compare_finds_zombies(
        self,
        settings: Settings,
        sample_endpoints: list[Endpoint],
        sample_openapi_spec: Path,
    ):
        """Test that deprecated endpoints are marked as Zombie."""
        engine = AuditEngine(settings)
        result = engine.compare(sample_endpoints, sample_openapi_spec)
        
        # /api/v0/legacy/auth is deprecated in spec
        assert len(result.zombie) >= 1


class TestSpecGenerator:
    """Tests for OpenAPI specification generation."""
    
    def test_generate_basic_spec(self, sample_endpoints: list[Endpoint]):
        """Test generating a basic specification."""
        generator = SpecGenerator()
        spec = generator.generate(
            sample_endpoints,
            title="Test API",
            version="1.0.0",
        )
        
        assert spec["openapi"] == "3.0.3"
        assert spec["info"]["title"] == "Test API"
        assert "paths" in spec
        assert len(spec["paths"]) > 0
    
    def test_generate_with_server(self, sample_endpoints: list[Endpoint]):
        """Test generating spec with server URL."""
        generator = SpecGenerator()
        spec = generator.generate(
            sample_endpoints,
            server_url="https://api.example.com",
        )
        
        assert "servers" in spec
        assert spec["servers"][0]["url"] == "https://api.example.com"
    
    def test_save_yaml(self, sample_endpoints: list[Endpoint], temp_dir: Path):
        """Test saving specification as YAML."""
        generator = SpecGenerator()
        spec = generator.generate(sample_endpoints)
        
        output_path = temp_dir / "generated.yaml"
        generator.save(spec, output_path, format="yaml")
        
        assert output_path.exists()
        content = output_path.read_text()
        assert "openapi:" in content


class TestSARIFGenerator:
    """Tests for SARIF report generation."""
    
    def test_generate_from_diff(
        self,
        settings: Settings,
        sample_endpoints: list[Endpoint],
        sample_openapi_spec: Path,
    ):
        """Test generating SARIF from diff results."""
        engine = AuditEngine(settings)
        diff = engine.compare(sample_endpoints, sample_openapi_spec)
        
        generator = SARIFGenerator()
        sarif = generator.generate_from_diff(diff)
        
        assert sarif["$schema"] is not None
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert "results" in sarif["runs"][0]
    
    def test_sarif_has_rules(
        self,
        settings: Settings,
        sample_endpoints: list[Endpoint],
        sample_openapi_spec: Path,
    ):
        """Test that SARIF includes rule definitions."""
        engine = AuditEngine(settings)
        diff = engine.compare(sample_endpoints, sample_openapi_spec)
        
        generator = SARIFGenerator()
        sarif = generator.generate_from_diff(diff)
        
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        
        assert "SHADOW-API-001" in rule_ids
        assert "SHADOW-API-002" in rule_ids
