"""Custom exceptions for Shadow API Mapper.

This module provides a hierarchy of specific exceptions for handling
known failure states gracefully while letting unexpected errors bubble up.
"""

from __future__ import annotations


class ShadowMapperError(Exception):
    """Base exception for all Shadow Mapper errors.
    
    All custom exceptions inherit from this class, allowing callers to
    catch all Shadow Mapper-specific errors with a single except clause.
    """
    pass


class ScopeViolationError(ShadowMapperError):
    """Raised when a target is outside the allowed scope."""
    pass


class URLValidationError(ScopeViolationError):
    """Raised when a URL fails strict validation (fail-closed).
    
    This distinguishes malformed URLs from valid URLs that are
    simply outside the allowed scope.
    """
    pass


class HarvestError(ShadowMapperError):
    """Raised during asset harvesting operations.
    
    This includes failures in:
    - Browser-based JavaScript collection
    - Wayback Machine archive mining
    - Subdomain enumeration
    """
    pass


class BrowserHarvestError(HarvestError):
    """Raised when browser-based harvesting fails."""
    pass


class WaybackHarvestError(HarvestError):
    """Raised when Wayback Machine mining fails."""
    pass


class SubdomainEnumerationError(HarvestError):
    """Raised when subdomain enumeration fails."""
    pass


class ParserError(ShadowMapperError):
    """Raised during source code parsing.
    
    This includes failures in:
    - Tree-sitter AST parsing
    - Endpoint extraction
    - Variable resolution
    - Secret detection
    """
    pass


class LanguageNotSupportedError(ParserError):
    """Raised when attempting to parse an unsupported language."""
    pass


class ProbeError(ShadowMapperError):
    """Raised during endpoint probing operations.
    
    This includes failures in:
    - HTTP request execution
    - Response classification
    - Zombie detection
    """
    pass


class NetworkTimeoutError(ProbeError):
    """Raised when a network request times out."""
    pass


class ConnectionError(ProbeError):
    """Raised when a network connection fails."""
    pass


class RateLimitError(ProbeError):
    """Raised when rate limiting is encountered and cannot be recovered."""
    pass


class AuditError(ShadowMapperError):
    """Raised during spec parsing or audit comparison.
    
    This includes failures in:
    - OpenAPI/Swagger spec parsing
    - Endpoint comparison
    - SARIF report generation
    """
    pass


class SpecParseError(AuditError):
    """Raised when OpenAPI/Swagger spec cannot be parsed."""
    pass


class CheckpointError(ShadowMapperError):
    """Raised during checkpoint save/load operations."""
    pass
