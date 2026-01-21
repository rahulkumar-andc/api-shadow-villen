"""Tests for the Parser module."""

import pytest
from pathlib import Path

from shadow_mapper.core.config import Settings
from shadow_mapper.parser import ParserEngine


class TestParserEngine:
    """Tests for the ParserEngine class."""
    
    def test_init(self, settings: Settings):
        """Test parser initialization."""
        parser = ParserEngine(settings)
        assert parser is not None
        assert parser.settings == settings
    
    def test_detect_language(self, settings: Settings):
        """Test language detection from file extension."""
        parser = ParserEngine(settings)
        
        assert parser._detect_language(Path("app.js")) == "javascript"
        assert parser._detect_language(Path("app.jsx")) == "javascript"
        assert parser._detect_language(Path("app.ts")) == "typescript"
        assert parser._detect_language(Path("app.tsx")) == "typescript"
        assert parser._detect_language(Path("app.py")) == "python"
        assert parser._detect_language(Path("app.txt")) is None
    
    def test_is_api_url(self, settings: Settings):
        """Test API URL detection."""
        parser = ParserEngine(settings)
        
        # Should match API URLs
        assert parser._is_api_url("/api/v1/users") is True
        assert parser._is_api_url("/api/admin/dashboard") is True
        assert parser._is_api_url("https://api.example.com/v2/products") is True
        assert parser._is_api_url("/graphql") is True
        assert parser._is_api_url("/rest/v1/items") is True
        
        # Should not match non-API URLs
        assert parser._is_api_url("/static/logo.png") is False
        assert parser._is_api_url("/images/banner.jpg") is False
        assert parser._is_api_url("/styles.css") is False
        assert parser._is_api_url("#section") is False
    
    def test_parse_file(self, settings: Settings, sample_js_file: Path):
        """Test parsing a JavaScript file."""
        parser = ParserEngine(settings)
        result = parser.parse_file(sample_js_file)
        
        assert result is not None
        assert result.source_file == sample_js_file
        # Should find some endpoints
        assert len(result.endpoints) > 0
    
    def test_parse_nonexistent_file(self, settings: Settings, temp_dir: Path):
        """Test parsing a file that doesn't exist."""
        parser = ParserEngine(settings)
        result = parser.parse_file(temp_dir / "nonexistent.js")
        
        assert result is not None
        assert len(result.errors) > 0
    
    def test_parse_directory(self, settings: Settings, sample_js_file: Path):
        """Test parsing a directory."""
        parser = ParserEngine(settings)
        results = parser.parse_directory(sample_js_file.parent)
        
        assert len(results) >= 1
        # Should have parsed our sample file
        parsed_files = [r.source_file for r in results]
        assert sample_js_file in parsed_files


class TestSecretDetection:
    """Tests for secret detection in parser."""
    
    def test_detect_api_key(self, settings: Settings, temp_dir: Path):
        """Test detection of API keys."""
        from shadow_mapper.parser.secrets import SecretDetector
        from shadow_mapper.core.models import Severity
        import re
        
        # Monkeypatch check patterns to avoid triggering GitHub secret scanning
        original_patterns = SecretDetector.SECRET_PATTERNS
        try:
            # Add a safe test pattern
            SecretDetector.SECRET_PATTERNS = [
                {
                    "name": "stripe_key", 
                    "pattern": re.compile(r'safe_stripe_[a-z0-9]+'),
                    "severity": Severity.CRITICAL
                },
                {
                    "name": "aws_access_key", 
                    "pattern": re.compile(r'SAFE_AWS_[A-Z0-9]+'),
                    "severity": Severity.CRITICAL
                },
            ]
            
            js_content = '''
            const STRIPE_KEY = "safe_stripe_123456789";
            const AWS_KEY = "SAFE_AWS_12345EXAMPLE";
            '''
            
            file_path = temp_dir / "secrets.js"
            file_path.write_text(js_content)
            
            settings.parser.detect_secrets = True
            parser = ParserEngine(settings)
            result = parser.parse_file(file_path)
            
            # Should detect secrets
            assert len(result.secrets) >= 1
            
        finally:
            # Restore patterns
            SecretDetector.SECRET_PATTERNS = original_patterns


class TestVariableResolution:
    """Tests for variable resolution."""
    
    def test_resolve_concatenated_url(self, settings: Settings, temp_dir: Path):
        """Test resolving concatenated URLs."""
        js_content = '''
        const BASE = "/api/v1";
        const USERS = "/users";
        fetch(BASE + USERS);
        '''
        
        file_path = temp_dir / "concat.js"
        file_path.write_text(js_content)
        
        settings.parser.resolve_variables = True
        parser = ParserEngine(settings)
        result = parser.parse_file(file_path)
        
        # Should find the endpoint with resolved URL
        assert len(result.endpoints) >= 1
