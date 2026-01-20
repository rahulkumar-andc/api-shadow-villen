"""OpenAPI specification comparison and diff analysis."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

import yaml
from rich.console import Console

from shadow_mapper.core.config import Settings
from shadow_mapper.core.models import (
    DiffResult,
    Endpoint,
    EndpointStatus,
    HTTPMethod,
    SpecEndpoint,
)

console = Console()


class SpecParser:
    """
    Parser for OpenAPI/Swagger specifications.
    
    Supports OpenAPI 3.x and Swagger 2.0.
    """
    
    def __init__(self):
        self._spec: dict = {}
        self._version: str = ""
    
    def parse(self, spec_path: Path) -> list[SpecEndpoint]:
        """
        Parse an OpenAPI specification file.
        
        Args:
            spec_path: Path to spec file (YAML or JSON)
            
        Returns:
            List of SpecEndpoint objects
        """
        # Load spec file
        with open(spec_path) as f:
            if spec_path.suffix in (".yaml", ".yml"):
                self._spec = yaml.safe_load(f)
            else:
                import json
                self._spec = json.load(f)
        
        # Detect version
        if "openapi" in self._spec:
            self._version = self._spec.get("openapi", "3.0.0")
            return self._parse_openapi3()
        elif "swagger" in self._spec:
            self._version = self._spec.get("swagger", "2.0")
            return self._parse_swagger2()
        else:
            raise ValueError("Unknown specification format")
    
    def _parse_openapi3(self) -> list[SpecEndpoint]:
        """Parse OpenAPI 3.x specification."""
        endpoints = []
        
        paths = self._spec.get("paths", {})
        
        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            
            for method in ["get", "post", "put", "delete", "patch", "options", "head"]:
                if method in path_item:
                    operation = path_item[method]
                    
                    endpoints.append(SpecEndpoint(
                        path=path,
                        method=HTTPMethod(method.upper()),
                        summary=operation.get("summary", ""),
                        deprecated=operation.get("deprecated", False),
                        tags=operation.get("tags", []),
                    ))
        
        return endpoints
    
    def _parse_swagger2(self) -> list[SpecEndpoint]:
        """Parse Swagger 2.0 specification."""
        endpoints = []
        
        base_path = self._spec.get("basePath", "")
        paths = self._spec.get("paths", {})
        
        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            
            full_path = base_path + path if base_path else path
            
            for method in ["get", "post", "put", "delete", "patch", "options", "head"]:
                if method in path_item:
                    operation = path_item[method]
                    
                    endpoints.append(SpecEndpoint(
                        path=full_path,
                        method=HTTPMethod(method.upper()),
                        summary=operation.get("summary", ""),
                        deprecated=operation.get("deprecated", False),
                        tags=operation.get("tags", []),
                    ))
        
        return endpoints
    
    def get_base_url(self) -> Optional[str]:
        """Get the base URL from the specification."""
        if "servers" in self._spec:
            # OpenAPI 3.x
            servers = self._spec["servers"]
            if servers:
                return servers[0].get("url", "")
        elif "host" in self._spec:
            # Swagger 2.0
            host = self._spec["host"]
            schemes = self._spec.get("schemes", ["https"])
            base_path = self._spec.get("basePath", "")
            return f"{schemes[0]}://{host}{base_path}"
        
        return None


class AuditEngine:
    """
    Compares discovered endpoints against an OpenAPI specification.
    
    Identifies:
    - Documented: Endpoints in both discovery and spec
    - Shadow: Endpoints in discovery but not spec (undocumented)
    - Ghost: Endpoints in spec but not responding (missing implementation)
    - Zombie: Deprecated endpoints still active
    """
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.spec_parser = SpecParser()
    
    def compare(
        self,
        discovered: list[Endpoint],
        spec_path: Path,
    ) -> DiffResult:
        """
        Compare discovered endpoints against an OpenAPI spec.
        
        Args:
            discovered: List of discovered Endpoint objects
            spec_path: Path to OpenAPI specification
            
        Returns:
            DiffResult with categorized endpoints
        """
        result = DiffResult()
        
        # Parse specification
        try:
            spec_endpoints = self.spec_parser.parse(spec_path)
        except Exception as e:
            console.print(f"  [red]Error parsing spec: {e}[/red]")
            return result
        
        # Build signature sets for comparison
        spec_signatures = self._build_spec_signatures(spec_endpoints)
        discovered_signatures = {ep.signature(): ep for ep in discovered}
        
        # Categorize discovered endpoints
        for ep in discovered:
            sig = ep.signature()
            normalized_sig = self._normalize_signature(sig)
            
            # Check if it matches any spec endpoint
            matched = False
            for spec_sig in spec_signatures:
                if self._signatures_match(normalized_sig, spec_sig):
                    matched = True
                    
                    # Check if deprecated
                    spec_ep = spec_signatures[spec_sig]
                    if spec_ep.deprecated:
                        ep.status = EndpointStatus.ZOMBIE
                        result.zombie.append(ep)
                    else:
                        ep.status = EndpointStatus.DOCUMENTED
                        result.documented.append(ep)
                    break
            
            if not matched:
                # Shadow API - exists in reality but not in spec
                ep.status = EndpointStatus.SHADOW
                result.shadow.append(ep)
        
        # Find ghost endpoints (in spec but not discovered)
        for spec_sig, spec_ep in spec_signatures.items():
            found = False
            for disc_sig in discovered_signatures:
                if self._signatures_match(self._normalize_signature(disc_sig), spec_sig):
                    found = True
                    break
            
            if not found:
                result.ghost.append(spec_ep)
        
        return result
    
    def _build_spec_signatures(
        self,
        spec_endpoints: list[SpecEndpoint],
    ) -> dict[str, SpecEndpoint]:
        """Build normalized signatures from spec endpoints."""
        signatures = {}
        
        for ep in spec_endpoints:
            # Normalize path parameters
            normalized_path = re.sub(r'\{[^}]+\}', '{param}', ep.path)
            sig = f"{ep.method.value}:{normalized_path}"
            signatures[sig] = ep
        
        return signatures
    
    def _normalize_signature(self, signature: str) -> str:
        """Normalize an endpoint signature for comparison."""
        method, path = signature.split(":", 1)
        
        # Normalize path parameters
        # Handle {param}, :param, and <param> styles
        normalized = re.sub(r'\{[^}]+\}', '{param}', path)
        normalized = re.sub(r':[a-zA-Z_]+', '{param}', normalized)
        normalized = re.sub(r'<[^>]+>', '{param}', normalized)
        
        # Remove trailing slashes
        normalized = normalized.rstrip("/")
        
        return f"{method}:{normalized}"
    
    def _signatures_match(self, sig1: str, sig2: str) -> bool:
        """Check if two signatures match (with parameter normalization)."""
        return sig1 == sig2
    
    def to_sarif(self, diff_result: DiffResult) -> dict:
        """Convert diff results to SARIF format."""
        from shadow_mapper.auditor.sarif import SARIFGenerator
        
        generator = SARIFGenerator()
        return generator.generate_from_diff(diff_result)
