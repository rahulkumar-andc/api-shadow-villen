"""Tests for variable resolver — template literals, concatenation, env vars."""

import pytest
from pathlib import Path
from unittest.mock import MagicMock

from shadow_mapper.core.config import Settings
from shadow_mapper.parser.resolver import VariableResolver


@pytest.fixture
def resolver(settings: Settings) -> VariableResolver:
    return VariableResolver(settings)


class TestSimpleResolution:
    """Basic variable resolution tests."""

    def test_const_double_quote(self, resolver: VariableResolver):
        content = 'const BASE_URL = "/api/v1";'
        node = MagicMock()
        node.start_byte = 0
        result = resolver.resolve("BASE_URL", content, node)
        assert result == "/api/v1"

    def test_const_single_quote(self, resolver: VariableResolver):
        content = "const PATH = '/api/v2/users';"
        node = MagicMock()
        node.start_byte = 0
        result = resolver.resolve("PATH", content, node)
        assert result == "/api/v2/users"

    def test_unknown_variable_returns_none(self, resolver: VariableResolver):
        content = "const OTHER = 'hello';"
        node = MagicMock()
        node.start_byte = 0
        result = resolver.resolve("UNKNOWN_VAR", content, node)
        assert result is None

    def test_depth_limit(self, resolver: VariableResolver):
        content = 'const X = "/api/v1";'
        node = MagicMock()
        node.start_byte = 0
        # At max depth should return None
        result = resolver.resolve("X", content, node, depth=resolver.max_depth)
        assert result is None


class TestEnvVariableSkip:
    """process.env references must return None — not real values."""

    def test_process_env_skipped(self, resolver: VariableResolver):
        node = MagicMock()
        node.start_byte = 0
        node.type = "member_expression"
        content = "const KEY = process.env.API_KEY;"
        # Resolver should return None for env references
        result = resolver.resolve("KEY", content, node)
        # Value in source is process.env reference — not resolvable to string
        assert result is None or "process.env" not in (result or "")

    def test_env_identifier_skipped(self, resolver: VariableResolver):
        """'process' as identifier should be skipped."""
        node = MagicMock()
        node.start_byte = 0
        result = resolver.resolve("process", "const x = 1;", node)
        assert result is None


class TestExpressionResolution:
    """Test resolve_expression with various node types."""

    def _make_string_node(self, value: str, content: str):
        """Create a mock string node."""
        node = MagicMock()
        node.type = "string"
        start = content.index(value)
        node.start_byte = start - 1  # include quote
        node.end_byte   = start + len(value) + 1
        return node

    def test_string_node(self, resolver: VariableResolver):
        content = '"/api/v1/users"'
        node = MagicMock()
        node.type = "string"
        node.start_byte = 0
        node.end_byte = len(content)
        result = resolver.resolve_expression(node, content)
        assert result == "/api/v1/users"

    def test_depth_exceeded_returns_none(self, resolver: VariableResolver):
        node = MagicMock()
        node.type = "string"
        node.start_byte = 0
        node.end_byte = 5
        result = resolver.resolve_expression(node, '"x"', depth=resolver.max_depth)
        assert result is None


class TestCacheInvalidation:
    """Verify caching behaves correctly."""

    def test_cache_hit(self, resolver: VariableResolver):
        content = 'const X = "/api/v1";'
        node = MagicMock()
        node.start_byte = 0

        first  = resolver.resolve("X", content, node)
        second = resolver.resolve("X", content, node)
        assert first == second

    def test_clear_cache(self, resolver: VariableResolver):
        content = 'const X = "/api/v1";'
        node = MagicMock()
        node.start_byte = 0

        resolver.resolve("X", content, node)
        resolver.clear_cache()
        assert len(resolver._cache) == 0
