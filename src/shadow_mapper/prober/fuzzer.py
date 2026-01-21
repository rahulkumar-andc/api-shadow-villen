"""Fuzzing engine for discovering hidden parameters and vulnerabilities.

Performs:
- Shadow parameter discovery (e.g. ?admin=true)
- Mass assignment detection (e.g. JSON body manipulation)
- HTTP Verb tampering
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx
from rich.console import Console

from shadow_mapper.core.models import Endpoint, HTTPMethod
from shadow_mapper.core.config import Settings

console = Console()


@dataclass
class FuzzResult:
    """Result of a fuzzing attempt."""
    
    endpoint: str
    parameter: str
    attack_type: str  # "shadow_param", "mass_assignment", "verb_tampering"
    payload: Any
    status_code: int
    confidence: str = "medium"  # low, medium, high
    description: str = ""


class FuzzerEngine:
    """Engine for active fuzzing of discovered endpoints."""
    
    # Common hidden parameters to probe
    SHADOW_PARAMS = [
        "admin", "debug", "test", "root", "super", 
        "privilege", "role", "internal", "config",
        "verbose", "show_all", "trace", "source"
    ]
    
    # Values to try for boolean-like params
    BOOLEAN_PAYLOADS = ["true", "1", "yes", "on"]
    
    # Mass assignment sensitive fields to attempt injecting
    SENSITIVE_FIELDS = {
        "role": "admin",
        "is_admin": True,
        "isAdmin": True,
        "permissions": ["all", "admin"],
        "groups": ["admin"],
        "access_level": "100",
        "plan": "premium",
        "subscription": "enterprise"
    }
    
    def __init__(self, settings: Settings, concurrency: int = 5):
        self.settings = settings
        self.concurrency = concurrency
        self._client: Optional[httpx.AsyncClient] = None
        self._sem = asyncio.Semaphore(concurrency)

    async def _get_client(self) -> httpx.AsyncClient:
        if not self._client:
            self._client = httpx.AsyncClient(
                verify=False,
                timeout=10.0,
                follow_redirects=True
            )
        return self._client
    
    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None

    async def fuzz_endpoint(self, endpoint: Endpoint) -> List[FuzzResult]:
        """Run all fuzzing checks against a single endpoint."""
        results = []
        
        # 1. Shadow Parameter Discovery (GET/POST params)
        results.extend(await self._fuzz_shadow_params(endpoint))
        
        # 2. Mass Assignment (JSON body)
        if endpoint.method in [HTTPMethod.POST, HTTPMethod.PUT, HTTPMethod.PATCH]:
            results.extend(await self._fuzz_mass_assignment(endpoint))
            
        return results

    async def _fuzz_shadow_params(self, endpoint: Endpoint) -> List[FuzzResult]:
        """Probe for hidden query parameters."""
        results = []
        client = await self._get_client()
        
        # Base request to get baseline
        try:
            async with self._sem:
                baseline = await client.request(endpoint.method, endpoint.url)
        except Exception:
            return []

        # Try each parameter
        for param in self.SHADOW_PARAMS:
            for val in self.BOOLEAN_PAYLOADS:
                try:
                    # Construct URL with param
                    fuzz_url = f"{endpoint.url}{'&' if '?' in endpoint.url else '?'}{param}={val}"
                    
                    async with self._sem:
                        response = await client.request(endpoint.method, fuzz_url)
                    
                    # Detection logic: Status change or Size change
                    # Skip 404s/400s if possible, look for 200/401/403/500
                    if response.status_code != baseline.status_code:
                        results.append(FuzzResult(
                            endpoint=endpoint.url,
                            parameter=param,
                            attack_type="shadow_param",
                            payload=f"{param}={val}",
                            status_code=response.status_code,
                            description=f"Status code changed: {baseline.status_code} -> {response.status_code}"
                        ))
                    elif len(response.content) != len(baseline.content):
                        # Simple length check (could be improved with difflib)
                        diff_ratio = abs(len(response.content) - len(baseline.content)) / len(baseline.content)
                        if diff_ratio > 0.05: # >5% difference
                            results.append(FuzzResult(
                                endpoint=endpoint.url,
                                parameter=param,
                                attack_type="shadow_param",
                                payload=f"{param}={val}",
                                status_code=response.status_code,
                                description=f"Response size changed significantly ({int(diff_ratio*100)}%)"
                            ))
                            
                except Exception:
                    continue
                    
        return results

    async def _fuzz_mass_assignment(self, endpoint: Endpoint) -> List[FuzzResult]:
        """Probe for mass assignment in JSON bodies."""
        results = []
        client = await self._get_client()
        
        # Assume endpoint accepts JSON for now. 
        # In a real scenario, we'd infer schema from previous traffic or OpenAPI.
        # Here we attempt blind injection.
        
        for field_name, value in self.SENSITIVE_FIELDS.items():
            payload = {field_name: value}
            
            try:
                async with self._sem:
                    response = await client.request(
                        endpoint.method, 
                        endpoint.url, 
                        json=payload
                    )
                
                # Detection is hard blindly. Look for specific indicators:
                # 1. 200 OK (if auth was bypassed or field accepted)
                # 2. Reflected values in response ("role": "admin")
                if response.status_code < 400:
                    response_text = response.text.lower()
                    if field_name.lower() in response_text and str(value).lower() in response_text:
                        results.append(FuzzResult(
                            endpoint=endpoint.url,
                            parameter=field_name,
                            attack_type="mass_assignment",
                            payload=payload,
                            status_code=response.status_code,
                            confidence="high",
                            description=f"Injected field '{field_name}' reflected in response"
                        ))
                        
            except Exception:
                continue
                
        return results
