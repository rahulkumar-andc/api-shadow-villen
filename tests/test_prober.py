"""Tests for the Prober module."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

import httpx

from shadow_mapper.core.config import Settings
from shadow_mapper.core.models import Endpoint, HTTPMethod
from shadow_mapper.prober.heuristics import ResponseClassifier, ZombieDetector


class TestResponseClassifier:
    """Tests for response classification."""
    
    def test_classify_200(self):
        """Test classification of 200 OK response."""
        classifier = ResponseClassifier()
        
        response = MagicMock(spec=httpx.Response)
        response.status_code = 200
        response.headers = {"content-type": "application/json"}
        response.text = '{"success": true}'
        
        result = classifier.classify(response)
        
        assert result.category == "active"
        assert result.is_json_api is True
    
    def test_classify_401(self):
        """Test classification of 401 Unauthorized response."""
        classifier = ResponseClassifier()
        
        response = MagicMock(spec=httpx.Response)
        response.status_code = 401
        response.headers = {"content-type": "application/json"}
        response.text = '{"error": "unauthorized"}'
        
        result = classifier.classify(response)
        
        assert result.category == "protected"
        assert "authentication" in result.notes[0].lower()
    
    def test_classify_404(self):
        """Test classification of 404 Not Found response."""
        classifier = ResponseClassifier()
        
        response = MagicMock(spec=httpx.Response)
        response.status_code = 404
        response.headers = {"content-type": "text/html"}
        response.text = "Not Found"
        
        result = classifier.classify(response)
        
        assert result.category == "dead"
    
    def test_detect_stack_trace(self):
        """Test detection of stack traces in response."""
        classifier = ResponseClassifier()
        
        response = MagicMock(spec=httpx.Response)
        response.status_code = 500
        response.headers = {"content-type": "text/plain"}
        response.text = '''
        Traceback (most recent call last):
            File "app.py", line 42, in handler
                return do_something()
        TypeError: 'NoneType' object is not subscriptable
        '''
        
        result = classifier.classify(response)
        
        assert result.has_stack_trace is True
        assert result.category == "vulnerable"
    
    def test_detect_cors_wildcard(self):
        """Test detection of wildcard CORS."""
        classifier = ResponseClassifier()
        
        response = MagicMock(spec=httpx.Response)
        response.status_code = 200
        response.headers = {
            "content-type": "application/json",
            "access-control-allow-origin": "*",
        }
        response.text = "{}"
        
        result = classifier.classify(response)
        
        assert result.has_cors_issue is True


class TestZombieDetector:
    """Tests for zombie API detection."""
    
    def test_detect_deprecation_header(self):
        """Test detection of Deprecation header."""
        detector = ZombieDetector()
        
        response = MagicMock(spec=httpx.Response)
        response.status_code = 200
        response.headers = {
            "deprecation": "2024-01-15",
        }
        response.text = "{}"
        
        result = detector.detect(response)
        
        assert result.is_deprecated is True
        assert result.deprecation_date is not None
    
    def test_detect_sunset_header(self):
        """Test detection of Sunset header (RFC 8594)."""
        detector = ZombieDetector()
        
        response = MagicMock(spec=httpx.Response)
        response.status_code = 200
        response.headers = {
            "sunset": "2024-06-30",
        }
        response.text = "{}"
        
        result = detector.detect(response)
        
        assert result.is_deprecated is True
        assert result.sunset_date is not None
    
    def test_detect_x_deprecated(self):
        """Test detection of X-Deprecated header."""
        detector = ZombieDetector()
        
        response = MagicMock(spec=httpx.Response)
        response.status_code = 200
        response.headers = {
            "x-deprecated": "true",
        }
        response.text = "{}"
        
        result = detector.detect(response)
        
        assert result.is_deprecated is True
    
    def test_detect_deprecation_in_body(self):
        """Test detection of deprecation notice in response body."""
        detector = ZombieDetector()
        
        response = MagicMock(spec=httpx.Response)
        response.status_code = 200
        response.headers = {}
        response.text = '{"message": "This API is deprecated. Please use v2 instead."}'
        
        result = detector.detect(response)
        
        assert len(result.age_indicators) > 0
    
    def test_detect_old_server(self):
        """Test detection of outdated server version."""
        detector = ZombieDetector()
        
        response = MagicMock(spec=httpx.Response)
        response.status_code = 200
        response.headers = {
            "server": "Apache/1.3.42",
        }
        response.text = "{}"
        
        result = detector.detect(response)
        
        assert len(result.age_indicators) > 0
        assert any("Apache" in ind for ind in result.age_indicators)
