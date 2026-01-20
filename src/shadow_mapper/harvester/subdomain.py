"""Passive subdomain enumeration via crt.sh."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Set

import httpx
from rich.console import Console

from shadow_mapper.core.config import Settings
from shadow_mapper.core.safety import ScopeEnforcer

console = Console()


@dataclass
class SubdomainResult:
    """Result of subdomain enumeration."""
    
    subdomains: set[str] = field(default_factory=set)
    errors: list[str] = field(default_factory=list)
    
    @property
    def count(self) -> int:
        return len(self.subdomains)


class SubdomainEnumerator:
    """Passive subdomain enumeration using public sources."""
    
    CRT_SH_API = "https://crt.sh"
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.scope_enforcer = ScopeEnforcer(settings.scope)
    
    async def enumerate_crtsh(self, domain: str) -> set[str]:
        """
        Enumerate subdomains via crt.sh (Certificate Transparency logs).
        
        Args:
            domain: Root domain to enumerate
            
        Returns:
            Set of discovered subdomains
        """
        subdomains: set[str] = set()
        
        params = {
            "q": f"%.{domain}",
            "output": "json",
        }
        
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                console.print(f"  [dim]Querying crt.sh for {domain}...[/dim]")
                
                resp = await client.get(self.CRT_SH_API, params=params)
                
                if resp.status_code != 200:
                    return subdomains
                
                data = resp.json()
                
                for entry in data:
                    name_value = entry.get("name_value", "")
                    
                    # Handle multiple names (separated by newlines)
                    for name in name_value.split("\n"):
                        name = name.strip().lower()
                        
                        # Remove wildcard prefixes
                        if name.startswith("*."):
                            name = name[2:]
                        
                        # Validate it's a subdomain of target
                        if name.endswith(domain) and name != domain:
                            subdomains.add(name)
                
        except Exception as e:
            console.print(f"  [yellow]crt.sh query error: {e}[/yellow]")
        
        return subdomains
    
    async def enumerate_dns_dumpster(self, domain: str) -> set[str]:
        """
        Enumerate subdomains via DNS Dumpster (if available).
        
        Args:
            domain: Root domain to enumerate
            
        Returns:
            Set of discovered subdomains
        """
        # DNS Dumpster requires CSRF token, so we'll skip it for simplicity
        # In a production tool, you'd implement full browser automation
        return set()
    
    async def enumerate(self, domain: str) -> SubdomainResult:
        """
        Enumerate subdomains using all available sources.
        
        Args:
            domain: Root domain to enumerate
            
        Returns:
            SubdomainResult with all discovered subdomains
        """
        result = SubdomainResult()
        
        # Run all enumeration methods concurrently
        tasks = [
            self.enumerate_crtsh(domain),
            self.enumerate_dns_dumpster(domain),
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for r in results:
            if isinstance(r, set):
                result.subdomains.update(r)
            elif isinstance(r, Exception):
                result.errors.append(str(r))
        
        # Filter by scope
        if self.settings.scope.allowed_domains:
            allowed, blocked = self.scope_enforcer.filter_urls(
                [f"https://{s}" for s in result.subdomains]
            )
            result.subdomains = {s.replace("https://", "") for s in allowed}
        
        console.print(f"  [dim]Found {result.count} subdomains[/dim]")
        
        return result
    
    async def resolve_subdomains(
        self,
        subdomains: set[str],
        max_concurrent: int = 20,
    ) -> set[str]:
        """
        Filter subdomains to only those that resolve (have DNS records).
        
        Args:
            subdomains: Set of subdomains to check
            max_concurrent: Maximum concurrent DNS lookups
            
        Returns:
            Set of subdomains that resolve
        """
        import socket
        
        resolved: set[str] = set()
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def check_dns(subdomain: str) -> bool:
            async with semaphore:
                try:
                    # Use asyncio to wrap the blocking DNS lookup
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(
                        None,
                        socket.gethostbyname,
                        subdomain,
                    )
                    return True
                except socket.gaierror:
                    return False
        
        tasks = [(subdomain, check_dns(subdomain)) for subdomain in subdomains]
        
        for subdomain, task in tasks:
            try:
                if await task:
                    resolved.add(subdomain)
            except Exception:
                pass
        
        return resolved
