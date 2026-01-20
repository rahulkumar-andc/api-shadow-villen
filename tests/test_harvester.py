"""Tests for the Harvester module."""

import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from shadow_mapper.core.config import Settings
from shadow_mapper.core.safety import ScopeEnforcer


class TestScopeEnforcer:
    """Tests for scope enforcement."""
    
    def test_allow_all_when_no_patterns(self, settings: Settings):
        """Test that all domains are allowed when no patterns specified."""
        settings.scope.allowed_domains = []
        settings.scope.blocked_domains = []
        
        enforcer = ScopeEnforcer(settings.scope)
        
        assert enforcer.is_allowed("https://example.com/api") is True
        assert enforcer.is_allowed("https://other.com/api") is True
    
    def test_allow_matching_domain(self, settings: Settings):
        """Test that matching domains are allowed."""
        settings.scope.allowed_domains = ["*.example.com"]
        settings.scope.blocked_domains = []
        
        enforcer = ScopeEnforcer(settings.scope)
        
        assert enforcer.is_allowed("https://api.example.com/v1") is True
        assert enforcer.is_allowed("https://www.example.com/") is True
        assert enforcer.is_allowed("https://other.com/api") is False
    
    def test_block_matching_domain(self, settings: Settings):
        """Test that blocked domains are rejected."""
        settings.scope.allowed_domains = ["*"]
        settings.scope.blocked_domains = ["*.gov", "localhost"]
        
        enforcer = ScopeEnforcer(settings.scope)
        
        assert enforcer.is_allowed("https://api.gov/v1") is False
        assert enforcer.is_allowed("http://localhost:8080/api") is False
        assert enforcer.is_allowed("https://example.com/api") is True
    
    def test_block_takes_precedence(self, settings: Settings):
        """Test that blocklist takes precedence over allowlist."""
        settings.scope.allowed_domains = ["*.example.com"]
        settings.scope.blocked_domains = ["admin.example.com"]
        
        enforcer = ScopeEnforcer(settings.scope)
        
        assert enforcer.is_allowed("https://api.example.com/v1") is True
        assert enforcer.is_allowed("https://admin.example.com/v1") is False
    
    def test_filter_urls(self, settings: Settings):
        """Test filtering a list of URLs."""
        settings.scope.allowed_domains = ["*.example.com"]
        settings.scope.blocked_domains = []
        
        enforcer = ScopeEnforcer(settings.scope)
        
        urls = [
            "https://api.example.com/v1",
            "https://other.com/api",
            "https://www.example.com/",
        ]
        
        allowed, blocked = enforcer.filter_urls(urls)
        
        assert len(allowed) == 2
        assert len(blocked) == 1
        assert "https://other.com/api" in blocked


class TestBrowserHarvester:
    """Tests for browser-based harvesting."""
    
    @pytest.mark.asyncio
    async def test_url_to_path_basic(self, settings: Settings):
        """Test URL to local path conversion."""
        from shadow_mapper.harvester.browser import BrowserHarvester
        
        harvester = BrowserHarvester(settings)
        
        path = harvester._url_to_path(
            "https://example.com/static/app.js",
            Path("/tmp/cache"),
        )
        
        assert path.name == "app.js"
        assert "example.com" in str(path)
    
    @pytest.mark.asyncio
    async def test_url_to_path_with_query(self, settings: Settings):
        """Test URL to path with query string."""
        from shadow_mapper.harvester.browser import BrowserHarvester
        
        harvester = BrowserHarvester(settings)
        
        path = harvester._url_to_path(
            "https://example.com/app.js?v=12345",
            Path("/tmp/cache"),
        )
        
        # Should include hash of query string
        assert "app" in path.name
        assert path.suffix == ".js"


class TestWaybackHarvester:
    """Tests for Wayback Machine integration."""
    
    @pytest.mark.asyncio
    async def test_parse_snapshot(self, settings: Settings):
        """Test parsing Wayback Machine snapshot data."""
        from shadow_mapper.harvester.archive import WaybackSnapshot
        
        snapshot = WaybackSnapshot(
            url="https://web.archive.org/web/20240101120000id_/https://example.com/app.js",
            timestamp="20240101120000",
            original_url="https://example.com/app.js",
            mime_type="application/javascript",
            status_code=200,
        )
        
        assert snapshot.datetime.year == 2024
        assert snapshot.datetime.month == 1
        assert "archive.org" in snapshot.archive_url
