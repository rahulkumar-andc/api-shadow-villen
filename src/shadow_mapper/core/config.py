"""Configuration management using Pydantic Settings."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ScopeSettings(BaseSettings):
    """Scope enforcement configuration."""
    
    allowed_domains: list[str] = Field(
        default_factory=list,
        description="List of allowed domain patterns (supports wildcards like *.example.com)"
    )
    
    blocked_domains: list[str] = Field(
        default=["localhost", "127.0.0.1", "0.0.0.0", "*.gov", "*.mil"],
        description="Domains that should never be scanned"
    )


class RateLimitSettings(BaseSettings):
    """Rate limiting configuration."""
    
    requests_per_second: float = Field(
        default=10.0,
        ge=0.1,
        le=100.0,
        description="Maximum requests per second"
    )
    
    burst: int = Field(
        default=20,
        ge=1,
        le=200,
        description="Burst capacity for rate limiting"
    )
    
    backoff_multiplier: float = Field(
        default=2.0,
        ge=1.0,
        le=5.0,
        description="Multiplier for exponential backoff"
    )
    
    max_backoff_seconds: int = Field(
        default=60,
        ge=1,
        le=300,
        description="Maximum backoff time in seconds"
    )


class HarvesterSettings(BaseSettings):
    """Harvester module configuration."""
    
    browser_timeout: int = Field(
        default=30000,
        ge=5000,
        le=120000,
        description="Browser page load timeout in milliseconds"
    )
    
    wait_for_idle: bool = Field(
        default=True,
        description="Wait for network idle before extracting assets"
    )
    
    extract_source_maps: bool = Field(
        default=True,
        description="Attempt to download and parse source maps"
    )
    
    wayback_months: int = Field(
        default=24,
        ge=1,
        le=120,
        description="How many months of history to search in Wayback Machine"
    )
    
    max_js_size_mb: float = Field(
        default=10.0,
        ge=0.1,
        le=50.0,
        description="Maximum JavaScript file size to download in MB"
    )


class ParserSettings(BaseSettings):
    """Parser module configuration."""
    
    languages: list[str] = Field(
        default=["javascript", "typescript", "python"],
        description="Languages to parse"
    )
    
    resolve_variables: bool = Field(
        default=True,
        description="Attempt to resolve variable values"
    )
    
    max_resolution_depth: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum depth for variable resolution"
    )
    
    detect_secrets: bool = Field(
        default=True,
        description="Enable secret detection"
    )


class ProberSettings(BaseSettings):
    """Prober module configuration."""
    
    timeout: int = Field(
        default=30,
        ge=5,
        le=120,
        description="HTTP request timeout in seconds"
    )
    
    follow_redirects: bool = Field(
        default=True,
        description="Follow HTTP redirects"
    )
    
    max_redirects: int = Field(
        default=5,
        ge=0,
        le=20,
        description="Maximum number of redirects to follow"
    )
    
    verify_ssl: bool = Field(
        default=True,
        description="Verify SSL certificates"
    )
    
    methods_to_test: list[str] = Field(
        default=["GET", "POST", "PUT", "DELETE", "PATCH"],
        description="HTTP methods to test for each endpoint"
    )
    
    version_permutations: bool = Field(
        default=True,
        description="Test version permutations (v1, v2, v3, etc.)"
    )
    
    max_version: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Maximum version number to test"
    )
    
    user_agent: str = Field(
        default="ShadowMapper/1.0 (+https://github.com/villen/shadow-api-mapper)",
        description="User-Agent header for requests"
    )


class AuditorSettings(BaseSettings):
    """Auditor module configuration."""
    
    spec_format: Literal["openapi3", "openapi2", "auto"] = Field(
        default="auto",
        description="OpenAPI specification format"
    )
    
    generate_skeleton: bool = Field(
        default=True,
        description="Generate skeleton specs for undocumented endpoints"
    )
    
    redact_pii: bool = Field(
        default=True,
        description="Redact PII from reports"
    )


class OutputSettings(BaseSettings):
    """Output configuration."""
    
    format: Literal["sarif", "json", "csv", "html"] = Field(
        default="sarif",
        description="Output report format"
    )
    
    output_dir: Path = Field(
        default=Path("./output"),
        description="Output directory for reports and cached assets"
    )
    
    verbose: bool = Field(
        default=False,
        description="Enable verbose output"
    )


class Settings(BaseSettings):
    """Main configuration container."""
    
    model_config = SettingsConfigDict(
        env_prefix="SHADOW_MAPPER_",
        env_nested_delimiter="__",
        case_sensitive=False,
    )
    
    # Sub-configurations
    scope: ScopeSettings = Field(default_factory=ScopeSettings)
    rate_limit: RateLimitSettings = Field(default_factory=RateLimitSettings)
    harvester: HarvesterSettings = Field(default_factory=HarvesterSettings)
    parser: ParserSettings = Field(default_factory=ParserSettings)
    prober: ProberSettings = Field(default_factory=ProberSettings)
    auditor: AuditorSettings = Field(default_factory=AuditorSettings)
    output: OutputSettings = Field(default_factory=OutputSettings)
    
    # Global settings
    dry_run: bool = Field(
        default=False,
        description="Dry run mode - no actual network requests"
    )
    
    @classmethod
    def from_yaml(cls, path: Path) -> "Settings":
        """Load settings from a YAML configuration file."""
        import yaml
        
        if not path.exists():
            return cls()
        
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        
        return cls(**data)
    
    @classmethod
    def from_file_or_default(cls, path: Path | None = None) -> "Settings":
        """Load from file if exists, otherwise return defaults."""
        default_paths = [
            Path("shadow-mapper.yaml"),
            Path("shadow-mapper.yml"),
            Path(".shadow-mapper.yaml"),
            Path.home() / ".config" / "shadow-mapper" / "config.yaml",
        ]
        
        if path and path.exists():
            return cls.from_yaml(path)
        
        for default_path in default_paths:
            if default_path.exists():
                return cls.from_yaml(default_path)
        
        return cls()
