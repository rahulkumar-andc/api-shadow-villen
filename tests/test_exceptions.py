"""Tests for custom exceptions module."""

import pytest

from shadow_mapper.core.exceptions import (
    AuditError,
    BrowserHarvestError,
    CheckpointError,
    ConnectionError,
    HarvestError,
    LanguageNotSupportedError,
    NetworkTimeoutError,
    ParserError,
    ProbeError,
    RateLimitError,
    ShadowMapperError,
    SpecParseError,
    SubdomainEnumerationError,
    WaybackHarvestError,
)


class TestExceptionHierarchy:
    """Tests for exception inheritance structure."""
    
    def test_base_exception_inherits_from_exception(self):
        """ShadowMapperError should inherit from Exception."""
        assert issubclass(ShadowMapperError, Exception)
    
    def test_harvest_error_inherits_from_base(self):
        """HarvestError should inherit from ShadowMapperError."""
        assert issubclass(HarvestError, ShadowMapperError)
    
    def test_browser_harvest_error_inherits_from_harvest(self):
        """BrowserHarvestError should inherit from HarvestError."""
        assert issubclass(BrowserHarvestError, HarvestError)
        assert issubclass(BrowserHarvestError, ShadowMapperError)
    
    def test_wayback_harvest_error_inherits_from_harvest(self):
        """WaybackHarvestError should inherit from HarvestError."""
        assert issubclass(WaybackHarvestError, HarvestError)
    
    def test_subdomain_error_inherits_from_harvest(self):
        """SubdomainEnumerationError should inherit from HarvestError."""
        assert issubclass(SubdomainEnumerationError, HarvestError)
    
    def test_parser_error_inherits_from_base(self):
        """ParserError should inherit from ShadowMapperError."""
        assert issubclass(ParserError, ShadowMapperError)
    
    def test_language_not_supported_inherits_from_parser(self):
        """LanguageNotSupportedError should inherit from ParserError."""
        assert issubclass(LanguageNotSupportedError, ParserError)
    
    def test_probe_error_inherits_from_base(self):
        """ProbeError should inherit from ShadowMapperError."""
        assert issubclass(ProbeError, ShadowMapperError)
    
    def test_network_timeout_inherits_from_probe(self):
        """NetworkTimeoutError should inherit from ProbeError."""
        assert issubclass(NetworkTimeoutError, ProbeError)
    
    def test_connection_error_inherits_from_probe(self):
        """ConnectionError should inherit from ProbeError."""
        assert issubclass(ConnectionError, ProbeError)
    
    def test_rate_limit_error_inherits_from_probe(self):
        """RateLimitError should inherit from ProbeError."""
        assert issubclass(RateLimitError, ProbeError)
    
    def test_audit_error_inherits_from_base(self):
        """AuditError should inherit from ShadowMapperError."""
        assert issubclass(AuditError, ShadowMapperError)
    
    def test_spec_parse_error_inherits_from_audit(self):
        """SpecParseError should inherit from AuditError."""
        assert issubclass(SpecParseError, AuditError)
    
    def test_checkpoint_error_inherits_from_base(self):
        """CheckpointError should inherit from ShadowMapperError."""
        assert issubclass(CheckpointError, ShadowMapperError)


class TestExceptionCatching:
    """Tests for catching exceptions at different levels."""
    
    def test_catch_specific_harvest_error(self):
        """Should be able to catch specific harvest errors."""
        with pytest.raises(BrowserHarvestError):
            raise BrowserHarvestError("Browser failed to initialize")
    
    def test_catch_harvest_error_catches_subclasses(self):
        """Catching HarvestError should catch all subclasses."""
        with pytest.raises(HarvestError):
            raise BrowserHarvestError("Browser failed")
        
        with pytest.raises(HarvestError):
            raise WaybackHarvestError("Wayback failed")
        
        with pytest.raises(HarvestError):
            raise SubdomainEnumerationError("Enumeration failed")
    
    def test_catch_base_catches_all(self):
        """Catching ShadowMapperError should catch all custom exceptions."""
        with pytest.raises(ShadowMapperError):
            raise HarvestError("Harvest failed")
        
        with pytest.raises(ShadowMapperError):
            raise ParserError("Parse failed")
        
        with pytest.raises(ShadowMapperError):
            raise ProbeError("Probe failed")
        
        with pytest.raises(ShadowMapperError):
            raise AuditError("Audit failed")
    
    def test_exception_message(self):
        """Exception should preserve error message."""
        error_msg = "Connection timed out after 30 seconds"
        try:
            raise NetworkTimeoutError(error_msg)
        except NetworkTimeoutError as e:
            assert str(e) == error_msg
    
    def test_exception_can_wrap_cause(self):
        """Exception should be able to wrap original cause."""
        original = ValueError("Invalid URL format")
        try:
            try:
                raise original
            except ValueError as e:
                raise HarvestError("Failed to harvest") from e
        except HarvestError as e:
            assert e.__cause__ is original
