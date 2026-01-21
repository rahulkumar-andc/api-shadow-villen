"""GraphQL endpoint detection and introspection.

Detects GraphQL endpoints and extracts schema information
via introspection queries.
"""

from __future__ import annotations

import json
from typing import Any, TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from shadow_mapper.core.models import Endpoint


# Standard GraphQL introspection query
INTROSPECTION_QUERY = '''
query IntrospectionQuery {
  __schema {
    types {
      name
      kind
      fields {
        name
        args {
          name
          type {
            name
            kind
          }
        }
        type {
          name
          kind
        }
      }
    }
    queryType { name }
    mutationType { name }
    subscriptionType { name }
  }
}
'''

# Simple query to test if endpoint responds as GraphQL
PROBE_QUERY = '''
query { __typename }
'''


class GraphQLDetector:
    """Detects and inspects GraphQL endpoints."""
    
    # Common GraphQL endpoint paths
    COMMON_PATHS = [
        "/graphql",
        "/graphql/",
        "/api/graphql",
        "/api/v1/graphql",
        "/v1/graphql",
        "/query",
        "/gql",
    ]
    
    def __init__(self, timeout: float = 10.0):
        """Initialize GraphQL detector.
        
        Args:
            timeout: HTTP request timeout in seconds
        """
        self.timeout = timeout
        self._client = None
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout)
        return self._client
    
    async def close(self) -> None:
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    async def is_graphql_endpoint(self, url: str) -> bool:
        """Check if URL responds as a GraphQL endpoint.
        
        Args:
            url: Full URL to test
            
        Returns:
            True if endpoint responds to GraphQL queries
        """
        client = await self._get_client()
        
        try:
            response = await client.post(
                url,
                json={"query": PROBE_QUERY},
                headers={"Content-Type": "application/json"},
            )
            
            if response.status_code == 200:
                data = response.json()
                # GraphQL always returns data or errors
                if "data" in data or "errors" in data:
                    return True
                    
        except Exception:
            pass
        
        return False
    
    async def discover_graphql_endpoints(
        self,
        base_url: str,
    ) -> list[str]:
        """Discover GraphQL endpoints at common paths.
        
        Args:
            base_url: Base URL of the target (e.g., https://api.example.com)
            
        Returns:
            List of discovered GraphQL endpoint URLs
        """
        base_url = base_url.rstrip("/")
        discovered = []
        
        for path in self.COMMON_PATHS:
            url = f"{base_url}{path}"
            if await self.is_graphql_endpoint(url):
                discovered.append(url)
        
        return discovered
    
    async def introspect(self, url: str) -> dict[str, Any] | None:
        """Run introspection query on GraphQL endpoint.
        
        Args:
            url: GraphQL endpoint URL
            
        Returns:
            Schema data or None if introspection is disabled
        """
        client = await self._get_client()
        
        try:
            response = await client.post(
                url,
                json={"query": INTROSPECTION_QUERY},
                headers={"Content-Type": "application/json"},
            )
            
            if response.status_code == 200:
                data = response.json()
                if "data" in data and "__schema" in data["data"]:
                    return data["data"]["__schema"]
                    
        except Exception:
            pass
        
        return None
    
    def extract_operations(
        self,
        schema: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Extract query/mutation operations from schema.
        
        Args:
            schema: Introspected GraphQL schema
            
        Returns:
            List of operations with name, type, and arguments
        """
        operations = []
        
        # Get root type names
        query_type = schema.get("queryType", {}).get("name", "Query")
        mutation_type = schema.get("mutationType", {}).get("name", "Mutation")
        
        # Find operations in types
        for type_def in schema.get("types", []):
            type_name = type_def.get("name", "")
            
            if type_name in (query_type, mutation_type):
                op_type = "query" if type_name == query_type else "mutation"
                
                for field in type_def.get("fields", []) or []:
                    operations.append({
                        "name": field.get("name"),
                        "type": op_type,
                        "args": [
                            {
                                "name": arg.get("name"),
                                "type": arg.get("type", {}).get("name"),
                            }
                            for arg in field.get("args", []) or []
                        ],
                        "return_type": field.get("type", {}).get("name"),
                    })
        
        return operations


async def detect_graphql_in_endpoints(
    endpoints: list["Endpoint"],
) -> list[str]:
    """Check discovered endpoints for GraphQL.
    
    Args:
        endpoints: List of discovered endpoints
        
    Returns:
        List of GraphQL endpoint URLs
    """
    detector = GraphQLDetector()
    graphql_endpoints = []
    
    try:
        for ep in endpoints:
            url = ep.url
            # Check if URL looks like it could be GraphQL
            if any(path in url.lower() for path in ["graphql", "gql", "query"]):
                if await detector.is_graphql_endpoint(url):
                    graphql_endpoints.append(url)
    finally:
        await detector.close()
    
    return graphql_endpoints
