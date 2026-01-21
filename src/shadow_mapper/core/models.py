"""Data models for Shadow-API Mapper."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class EndpointStatus(str, Enum):
    """Status classification for discovered endpoints."""
    
    # Discovery states
    DISCOVERED = "discovered"
    VERIFIED = "verified"
    DEAD = "dead"
    
    # Governance states
    DOCUMENTED = "documented"
    SHADOW = "shadow"
    ZOMBIE = "zombie"
    GHOST = "ghost"
    
    # Security states
    PROTECTED = "protected"
    UNPROTECTED = "unprotected"
    VULNERABLE = "vulnerable"


class Severity(str, Enum):
    """Severity levels for findings."""
    
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class HTTPMethod(str, Enum):
    """HTTP methods."""
    
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"


class SourceLocation(BaseModel):
    """Location where an endpoint was discovered."""
    
    file: Path
    line: int = 0
    column: int = 0
    context: str = ""
    
    def __str__(self) -> str:
        """Format as file:line:column."""
        return f"{self.file}:{self.line}:{self.column}"


class Endpoint(BaseModel):
    """Represents a discovered API endpoint."""
    
    url: str = Field(..., description="Full URL or path of the endpoint")
    method: HTTPMethod = Field(default=HTTPMethod.GET, description="HTTP method")
    
    # Discovery metadata
    source: SourceLocation | None = Field(
        default=None, 
        description="Where this endpoint was found"
    )
    discovered_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When this endpoint was discovered"
    )
    
    # Parameters found in source
    path_params: list[str] = Field(
        default_factory=list,
        description="Path parameters (e.g., {id}, :userId)"
    )
    query_params: list[str] = Field(
        default_factory=list,
        description="Query parameters found"
    )
    headers: dict[str, str] = Field(
        default_factory=dict,
        description="Headers found in source"
    )
    body_schema: dict[str, Any] | None = Field(
        default=None,
        description="Request body schema if detected"
    )
    
    # Status
    status: EndpointStatus = Field(
        default=EndpointStatus.DISCOVERED,
        description="Current status of this endpoint"
    )
    
    # Verification results
    http_status: int | None = Field(
        default=None,
        description="HTTP status code from verification"
    )
    response_time_ms: float | None = Field(
        default=None,
        description="Response time in milliseconds"
    )
    content_type: str | None = Field(
        default=None,
        description="Content-Type from response"
    )
    
    # Zombie detection
    deprecation_date: datetime | None = Field(
        default=None,
        description="Deprecation date from headers"
    )
    sunset_date: datetime | None = Field(
        default=None,
        description="Sunset date from headers"
    )
    
    def signature(self) -> str:
        """Generate a unique signature for this endpoint."""
        # Normalize path by replacing param placeholders
        import re
        normalized = re.sub(r'\{[^}]+\}', '{param}', self.url)
        normalized = re.sub(r':[a-zA-Z_]+', ':param', normalized)
        # Handle both enum and string method values
        method_str = self.method.value if hasattr(self.method, 'value') else str(self.method)
        return f"{method_str}:{normalized}"
    
    model_config = ConfigDict(use_enum_values=True)


class Secret(BaseModel):
    """A detected secret or sensitive value."""
    
    type: str = Field(..., description="Type of secret (api_key, token, etc.)")
    value: str = Field(..., description="The secret value (may be redacted)")
    source: SourceLocation
    severity: Severity = Severity.HIGH
    redacted: bool = Field(default=False, description="Whether value is redacted")
    
    def redact(self) -> "Secret":
        """Return a redacted copy of this secret."""
        if self.redacted:
            return self
        
        # Keep first 4 and last 4 chars, mask middle
        if len(self.value) > 12:
            masked = self.value[:4] + "*" * (len(self.value) - 8) + self.value[-4:]
        else:
            masked = "*" * len(self.value)
        
        return Secret(
            type=self.type,
            value=masked,
            source=self.source,
            severity=self.severity,
            redacted=True,
        )


class ScanResult(BaseModel):
    """Result of scanning a single source file."""
    
    source_file: Path
    endpoints: list[Endpoint] = Field(default_factory=list)
    secrets: list[Secret] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    parse_time_ms: float = 0.0
    
    @property
    def endpoint_count(self) -> int:
        return len(self.endpoints)
    
    @property
    def secret_count(self) -> int:
        return len(self.secrets)


class ProbeResult(BaseModel):
    """Result of probing an endpoint."""
    
    endpoint: Endpoint
    success: bool
    http_status: int | None = None
    response_time_ms: float | None = None
    content_type: str | None = None
    content_length: int | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    error: str | None = None
    
    # Zombie indicators
    has_deprecation_header: bool = False
    deprecation_date: datetime | None = None
    sunset_date: datetime | None = None
    
    # Vulnerability indicators
    exposes_stack_trace: bool = False
    has_cors_misconfiguration: bool = False


class SpecEndpoint(BaseModel):
    """An endpoint from an OpenAPI specification."""
    
    path: str
    method: HTTPMethod
    summary: str = ""
    deprecated: bool = False
    tags: list[str] = Field(default_factory=list)


class DiffResult(BaseModel):
    """Result of comparing discovered endpoints against a spec."""
    
    documented: list[Endpoint] = Field(
        default_factory=list,
        description="Endpoints found in both discovery and spec"
    )
    shadow: list[Endpoint] = Field(
        default_factory=list,
        description="Endpoints found in discovery but not in spec"
    )
    ghost: list[SpecEndpoint] = Field(
        default_factory=list,
        description="Endpoints in spec but not responding"
    )
    zombie: list[Endpoint] = Field(
        default_factory=list,
        description="Deprecated endpoints still active"
    )


class ScanReport(BaseModel):
    """Complete scan report."""
    
    # Metadata
    scan_id: str = Field(..., description="Unique scan identifier")
    target: str = Field(..., description="Target URL or repository")
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None
    duration_seconds: float = 0.0
    
    # Configuration used
    dry_run: bool = False
    
    # Results
    total_files_scanned: int = 0
    total_endpoints_discovered: int = 0
    total_endpoints_verified: int = 0
    
    endpoints: list[Endpoint] = Field(default_factory=list)
    secrets: list[Secret] = Field(default_factory=list)
    diff: DiffResult | None = None
    
    # Errors and warnings
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    
    def summary(self) -> dict[str, Any]:
        """Generate a summary of findings."""
        status_counts: dict[str, int] = {}
        for ep in self.endpoints:
            status = ep.status.value if isinstance(ep.status, Enum) else ep.status
            status_counts[status] = status_counts.get(status, 0) + 1
        
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "duration_seconds": self.duration_seconds,
            "files_scanned": self.total_files_scanned,
            "endpoints": {
                "discovered": self.total_endpoints_discovered,
                "verified": self.total_endpoints_verified,
                "by_status": status_counts,
            },
            "secrets_found": len(self.secrets),
            "errors": len(self.errors),
        }
