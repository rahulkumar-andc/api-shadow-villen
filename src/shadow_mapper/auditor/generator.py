"""Automatic OpenAPI specification generation from discovered endpoints."""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import yaml
from rich.console import Console

from shadow_mapper.core.config import Settings
from shadow_mapper.core.models import Endpoint, HTTPMethod

console = Console()


class SpecGenerator:
    """
    Generates OpenAPI 3.0 specifications from discovered endpoints.
    
    Creates skeleton specs that can be used as a starting point for
    documenting previously undiscovered Shadow APIs.
    """
    
    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings
    
    def generate(
        self,
        endpoints: list[Endpoint],
        title: str = "Discovered API",
        version: str = "1.0.0",
        server_url: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Generate an OpenAPI 3.0 specification from endpoints.
        
        Args:
            endpoints: List of discovered Endpoint objects
            title: API title
            version: API version
            server_url: Base server URL
            
        Returns:
            OpenAPI specification as dictionary
        """
        spec: dict[str, Any] = {
            "openapi": "3.0.3",
            "info": {
                "title": title,
                "version": version,
                "description": f"Auto-generated specification from Shadow-API Mapper\nGenerated: {datetime.utcnow().isoformat()}Z",
            },
            "paths": {},
        }
        
        # Add server if provided
        if server_url:
            spec["servers"] = [{"url": server_url}]
        
        # Group endpoints by path
        paths: dict[str, dict] = {}
        
        for ep in endpoints:
            path = self._normalize_path(ep.url)
            method = ep.method.value.lower() if isinstance(ep.method, HTTPMethod) else ep.method.lower()
            
            if path not in paths:
                paths[path] = {}
            
            # Build operation object
            operation = self._build_operation(ep)
            paths[path][method] = operation
        
        spec["paths"] = paths
        
        # Generate components/schemas if we have body schemas
        schemas = self._extract_schemas(endpoints)
        if schemas:
            spec["components"] = {"schemas": schemas}
        
        return spec
    
    def _normalize_path(self, url: str) -> str:
        """Normalize a URL to an OpenAPI path."""
        # Remove protocol and host
        path = re.sub(r'^https?://[^/]+', '', url)
        
        # Ensure starts with /
        if not path.startswith("/"):
            path = "/" + path
        
        # Remove query string
        path = path.split("?")[0]
        
        # Convert various param styles to OpenAPI style
        # :param -> {param}
        path = re.sub(r':([a-zA-Z_][a-zA-Z0-9_]*)', r'{\1}', path)
        
        return path
    
    def _build_operation(self, endpoint: Endpoint) -> dict[str, Any]:
        """Build an OpenAPI operation object from an endpoint."""
        operation: dict[str, Any] = {
            "summary": f"Discovered endpoint at {endpoint.url}",
            "description": self._generate_description(endpoint),
            "responses": {
                "200": {
                    "description": "Successful response",
                },
            },
        }
        
        # Add tags based on path
        tags = self._infer_tags(endpoint.url)
        if tags:
            operation["tags"] = tags
        
        # Add path parameters
        path_params = self._extract_path_params(endpoint.url)
        if path_params:
            operation["parameters"] = [
                {
                    "name": param,
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string"},
                }
                for param in path_params
            ]
        
        # Add query parameters
        if endpoint.query_params:
            if "parameters" not in operation:
                operation["parameters"] = []
            
            for param in endpoint.query_params:
                operation["parameters"].append({
                    "name": param,
                    "in": "query",
                    "required": False,
                    "schema": {"type": "string"},
                })
        
        # Add request body for POST/PUT/PATCH
        method = endpoint.method.value if isinstance(endpoint.method, HTTPMethod) else endpoint.method
        if method in ["POST", "PUT", "PATCH"]:
            operation["requestBody"] = {
                "content": {
                    "application/json": {
                        "schema": {"type": "object"},
                    },
                },
            }
        
        # Add security placeholder
        operation["security"] = [{}]  # Empty to indicate unknown
        
        # Add source information as extension
        if endpoint.source:
            operation["x-discovered-in"] = str(endpoint.source.file)
            operation["x-discovered-line"] = endpoint.source.line
        
        return operation
    
    def _generate_description(self, endpoint: Endpoint) -> str:
        """Generate a description for an operation."""
        parts = [
            "**Auto-discovered endpoint**",
            "",
            f"- **URL**: `{endpoint.url}`",
        ]
        
        if endpoint.source:
            parts.append(f"- **Found in**: `{endpoint.source.file}:{endpoint.source.line}`")
        
        if endpoint.http_status:
            parts.append(f"- **Verified status**: {endpoint.http_status}")
        
        if endpoint.status:
            status_val = endpoint.status.value if hasattr(endpoint.status, 'value') else endpoint.status
            parts.append(f"- **Classification**: {status_val}")
        
        parts.extend([
            "",
            "> ⚠️ This endpoint was discovered by Shadow-API Mapper and may not be fully documented.",
        ])
        
        return "\n".join(parts)
    
    def _infer_tags(self, url: str) -> list[str]:
        """Infer tags from URL path."""
        tags = []
        
        # Common API resource patterns
        resource_patterns = [
            (r'/users?/', "Users"),
            (r'/auth/', "Authentication"),
            (r'/admin/', "Admin"),
            (r'/orders?/', "Orders"),
            (r'/products?/', "Products"),
            (r'/payments?/', "Payments"),
            (r'/notifications?/', "Notifications"),
            (r'/settings?/', "Settings"),
            (r'/health', "Health"),
            (r'/metrics', "Metrics"),
            (r'/graphql', "GraphQL"),
        ]
        
        for pattern, tag in resource_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                tags.append(tag)
        
        # Extract version as tag
        version_match = re.search(r'/v(\d+)/', url)
        if version_match:
            tags.append(f"v{version_match.group(1)}")
        
        return tags or ["Discovered"]
    
    def _extract_path_params(self, url: str) -> list[str]:
        """Extract path parameter names from URL."""
        params = []
        
        # Match {param}, :param, <param> styles
        for match in re.finditer(r'\{([^}]+)\}|:([a-zA-Z_]+)|<([^>]+)>', url):
            param = match.group(1) or match.group(2) or match.group(3)
            if param:
                params.append(param)
        
        return params
    
    def _extract_schemas(self, endpoints: list[Endpoint]) -> dict[str, Any]:
        """Extract reusable schemas from endpoints."""
        schemas = {}
        
        for ep in endpoints:
            if ep.body_schema:
                # Generate schema name from URL
                name = self._schema_name_from_url(ep.url)
                if name and name not in schemas:
                    schemas[name] = ep.body_schema
        
        return schemas
    
    def _schema_name_from_url(self, url: str) -> Optional[str]:
        """Generate a schema name from URL."""
        # Extract resource name from URL
        parts = url.strip("/").split("/")
        
        for part in reversed(parts):
            # Skip version segments, params, etc.
            if re.match(r'^v\d+$', part):
                continue
            if re.match(r'^[{:<]', part):
                continue
            if part:
                # PascalCase the name
                return "".join(word.capitalize() for word in re.split(r'[-_]', part))
        
        return None
    
    def save(
        self,
        spec: dict[str, Any],
        output_path: Path,
        format: str = "yaml",
    ) -> None:
        """
        Save specification to file.
        
        Args:
            spec: OpenAPI specification dictionary
            output_path: Path to save to
            format: Output format ("yaml" or "json")
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, "w") as f:
            if format == "json":
                json.dump(spec, f, indent=2)
            else:
                yaml.dump(spec, f, default_flow_style=False, sort_keys=False)
        
        console.print(f"  [green]Specification saved to {output_path}[/green]")
