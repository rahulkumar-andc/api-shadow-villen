"""Async HTTP scanner for endpoint verification."""

from __future__ import annotations

import asyncio
import time
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx
from rich.console import Console
from rich.progress import Progress, TaskID

from shadow_mapper.core.config import Settings
from shadow_mapper.core.models import Endpoint, HTTPMethod, ProbeResult
from shadow_mapper.core.safety import RateLimiter, ScopeEnforcer
from shadow_mapper.prober.heuristics import ResponseClassifier, ZombieDetector
from shadow_mapper.prober.nuclei import NucleiScanner

console = Console()


class ProberEngine:
    """
    High-performance async HTTP scanner for endpoint verification.
    
    Features:
    - Concurrent scanning with configurable rate limiting
    - HTTP/2 support
    - Adaptive backoff on rate limiting
    - Response classification and zombie detection
    """
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.scope_enforcer = ScopeEnforcer(settings.scope)
        self.rate_limiter = RateLimiter(settings.rate_limit)
        self.classifier = ResponseClassifier()
        self.zombie_detector = ZombieDetector()
        self.nuclei_scanner = NucleiScanner(settings) if settings.prober else None
    
    async def probe_endpoints(
        self,
        endpoints: list[Endpoint],
        base_url: Optional[str] = None,
        run_nuclei: bool = False,
    ) -> list[ProbeResult]:
        """
        Probe a list of endpoints concurrently.
        
        Args:
            endpoints: List of endpoints to probe
            base_url: Optional base URL to prepend to relative paths
            run_nuclei: Whether to run Nuclei vulnerability scan
            
        Returns:
            List of ProbeResults
        """
        results: list[ProbeResult] = []
        
        # Deduplicate endpoints by signature
        seen_signatures: set[str] = set()
        unique_endpoints: list[Endpoint] = []
        
        for ep in endpoints:
            sig = ep.signature()
            if sig not in seen_signatures:
                seen_signatures.add(sig)
                unique_endpoints.append(ep)
        
        console.print(f"  [dim]Probing {len(unique_endpoints)} unique endpoints...[/dim]")
        
        # Create HTTP client
        async with httpx.AsyncClient(
            http2=True,
            timeout=httpx.Timeout(self.settings.prober.timeout),
            follow_redirects=self.settings.prober.follow_redirects,
            max_redirects=self.settings.prober.max_redirects,
            verify=self.settings.prober.verify_ssl,
            headers={
                "User-Agent": self.settings.prober.user_agent,
            },
        ) as client:
            # Create tasks for all endpoints
            tasks = [
                self._probe_one(client, ep, base_url)
                for ep in unique_endpoints
            ]
            
            # Execute with progress
            results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and convert to ProbeResult
        valid_results = []
        for result in results:
            if isinstance(result, ProbeResult):
                valid_results.append(result)
            elif isinstance(result, Exception):
                console.print(f"  [red]Probe error: {result}[/red]")
        
        # Run Nuclei if requested
        if run_nuclei and self.nuclei_scanner:
            active_urls = [
                r.endpoint.url for r in valid_results
                if r.success and r.http_status and r.http_status < 400
            ]
            if active_urls:
                console.print(f"  [dim]Running Nuclei on {len(active_urls)} active endpoints...[/dim]")
                await self.nuclei_scanner.scan(active_urls)
        
        # Summary
        active = sum(1 for r in valid_results if r.success and r.http_status and r.http_status < 400)
        protected = sum(1 for r in valid_results if r.http_status in [401, 403])
        dead = sum(1 for r in valid_results if not r.success or r.http_status == 404)
        
        console.print(f"  [green]Active: {active}[/green] | Protected: {protected} | Dead: {dead}")
        
        return valid_results
    
    async def _probe_one(
        self,
        client: httpx.AsyncClient,
        endpoint: Endpoint,
        base_url: Optional[str] = None,
    ) -> ProbeResult:
        """Probe a single endpoint."""
        # Acquire rate limit token
        await self.rate_limiter.acquire()
        
        # Build full URL
        url = endpoint.url
        if base_url and not url.startswith(("http://", "https://")):
            url = urljoin(base_url, url)
        elif not url.startswith(("http://", "https://")):
            # Skip relative URLs without base
            return ProbeResult(
                endpoint=endpoint,
                success=False,
                error="No base URL for relative path",
            )
        
        # Check scope
        if not self.scope_enforcer.is_allowed(url):
            return ProbeResult(
                endpoint=endpoint,
                success=False,
                error="URL out of scope",
            )
        
        start_time = time.time()
        
        try:
            # Make request
            method = endpoint.method.value if isinstance(endpoint.method, HTTPMethod) else endpoint.method
            response = await client.request(method, url)
            
            response_time = (time.time() - start_time) * 1000
            
            # Check for rate limiting
            if response.status_code == 429:
                self.rate_limiter.trigger_backoff()
            else:
                self.rate_limiter.reset_backoff()
            
            # Classify response
            classification = self.classifier.classify(response)
            
            # Check for zombie indicators
            zombie_info = self.zombie_detector.detect(response)
            
            return ProbeResult(
                endpoint=endpoint,
                success=True,
                http_status=response.status_code,
                response_time_ms=response_time,
                content_type=response.headers.get("content-type"),
                content_length=int(response.headers.get("content-length", 0)),
                headers=dict(response.headers),
                has_deprecation_header=zombie_info.is_deprecated,
                deprecation_date=zombie_info.deprecation_date,
                sunset_date=zombie_info.sunset_date,
                exposes_stack_trace=classification.has_stack_trace,
                has_cors_misconfiguration=classification.has_cors_issue,
            )
            
        except httpx.TimeoutException:
            return ProbeResult(
                endpoint=endpoint,
                success=False,
                error="Request timeout",
            )
        except httpx.ConnectError as e:
            return ProbeResult(
                endpoint=endpoint,
                success=False,
                error=f"Connection error: {str(e)}",
            )
        except Exception as e:
            return ProbeResult(
                endpoint=endpoint,
                success=False,
                error=str(e),
            )
    
    async def probe_with_version_permutation(
        self,
        endpoints: list[Endpoint],
        base_url: str,
    ) -> list[ProbeResult]:
        """
        Probe endpoints with version permutation to find zombie APIs.
        
        For each endpoint like /api/v2/users, also tests /api/v1/users, /api/v3/users, etc.
        """
        all_endpoints = list(endpoints)
        
        if self.settings.prober.version_permutations:
            import re
            
            version_pattern = re.compile(r'/v(\d+)/')
            
            for ep in endpoints:
                match = version_pattern.search(ep.url)
                if match:
                    current_version = int(match.group(1))
                    
                    # Generate version permutations
                    for v in range(1, self.settings.prober.max_version + 1):
                        if v != current_version:
                            new_url = version_pattern.sub(f'/v{v}/', ep.url)
                            new_endpoint = Endpoint(
                                url=new_url,
                                method=ep.method,
                                source=ep.source,
                            )
                            all_endpoints.append(new_endpoint)
        
        return await self.probe_endpoints(all_endpoints, base_url)
