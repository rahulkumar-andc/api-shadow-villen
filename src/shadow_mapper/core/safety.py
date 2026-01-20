"""Safety controls - Scope enforcement, rate limiting, and PII redaction."""

from __future__ import annotations

import asyncio
import fnmatch
import re
import time
from dataclasses import dataclass, field
from typing import Pattern
from urllib.parse import urlparse

from rich.console import Console

from shadow_mapper.core.config import RateLimitSettings, ScopeSettings

console = Console()


class ScopeViolationError(Exception):
    """Raised when a target is outside the allowed scope."""
    pass


class ScopeEnforcer:
    """Enforces scanning boundaries to prevent unauthorized access."""
    
    def __init__(self, settings: ScopeSettings):
        self.settings = settings
        self._allowed_patterns = self._compile_patterns(settings.allowed_domains)
        self._blocked_patterns = self._compile_patterns(settings.blocked_domains)
    
    def _compile_patterns(self, patterns: list[str]) -> list[str]:
        """Normalize domain patterns for matching."""
        normalized = []
        for pattern in patterns:
            # Remove protocol if present
            pattern = re.sub(r'^https?://', '', pattern)
            # Remove trailing slashes
            pattern = pattern.rstrip('/')
            normalized.append(pattern.lower())
        return normalized
    
    def _matches_pattern(self, domain: str, pattern: str) -> bool:
        """Check if domain matches a wildcard pattern."""
        # Convert wildcard pattern to fnmatch format
        # *.example.com -> matches sub.example.com
        return fnmatch.fnmatch(domain.lower(), pattern)
    
    def is_allowed(self, url: str) -> bool:
        """Check if a URL is within the allowed scope."""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
            
            # Check blocked first (blocklist takes precedence)
            for pattern in self._blocked_patterns:
                if self._matches_pattern(domain, pattern):
                    return False
            
            # If no allowed patterns specified, allow all (except blocked)
            if not self._allowed_patterns:
                return True
            
            # Check allowed patterns
            for pattern in self._allowed_patterns:
                if self._matches_pattern(domain, pattern):
                    return True
            
            return False
            
        except Exception:
            # If we can't parse the URL, deny by default
            return False
    
    def validate(self, url: str) -> None:
        """Validate URL and raise if out of scope."""
        if not self.is_allowed(url):
            raise ScopeViolationError(
                f"Target '{url}' is outside the allowed scope. "
                f"Allowed domains: {self.settings.allowed_domains or ['*']}, "
                f"Blocked domains: {self.settings.blocked_domains}"
            )
    
    def filter_urls(self, urls: list[str]) -> tuple[list[str], list[str]]:
        """Separate URLs into allowed and blocked lists."""
        allowed = []
        blocked = []
        
        for url in urls:
            if self.is_allowed(url):
                allowed.append(url)
            else:
                blocked.append(url)
        
        return allowed, blocked


@dataclass
class RateLimiter:
    """Token bucket rate limiter with adaptive backoff."""
    
    settings: RateLimitSettings
    tokens: float = field(init=False)
    last_update: float = field(init=False)
    backoff_until: float = field(init=False, default=0.0)
    current_backoff: float = field(init=False, default=1.0)
    
    def __post_init__(self):
        self.tokens = float(self.settings.burst)
        self.last_update = time.monotonic()
    
    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self.last_update
        self.last_update = now
        
        # Add tokens based on rate
        self.tokens = min(
            self.settings.burst,
            self.tokens + elapsed * self.settings.requests_per_second
        )
    
    async def acquire(self, tokens: int = 1) -> None:
        """Acquire tokens, waiting if necessary."""
        # Check if we're in backoff period
        now = time.monotonic()
        if now < self.backoff_until:
            wait_time = self.backoff_until - now
            console.print(f"[yellow]Rate limited, waiting {wait_time:.1f}s...[/yellow]")
            await asyncio.sleep(wait_time)
        
        self._refill()
        
        while self.tokens < tokens:
            # Calculate wait time
            needed = tokens - self.tokens
            wait_time = needed / self.settings.requests_per_second
            await asyncio.sleep(wait_time)
            self._refill()
        
        self.tokens -= tokens
    
    def trigger_backoff(self) -> None:
        """Trigger exponential backoff (called when rate limited by server)."""
        self.current_backoff = min(
            self.current_backoff * self.settings.backoff_multiplier,
            self.settings.max_backoff_seconds
        )
        self.backoff_until = time.monotonic() + self.current_backoff
        console.print(
            f"[yellow]Server rate limit detected, backing off for "
            f"{self.current_backoff:.1f}s[/yellow]"
        )
    
    def reset_backoff(self) -> None:
        """Reset backoff after successful request."""
        self.current_backoff = 1.0


class PIIRedactor:
    """Redacts personally identifiable information from text."""
    
    # PII patterns
    PATTERNS: list[tuple[str, Pattern[str]]] = [
        ("email", re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')),
        ("phone", re.compile(r'\b(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b')),
        ("ssn", re.compile(r'\b\d{3}-\d{2}-\d{4}\b')),
        ("credit_card", re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b')),
        ("ipv4", re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')),
        # API keys and tokens (common patterns)
        ("api_key", re.compile(r'\b(?:sk|pk|api|key|token|secret|password|auth)[-_]?[a-zA-Z0-9]{20,}\b', re.I)),
        ("bearer_token", re.compile(r'\bBearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b')),
        ("basic_auth", re.compile(r'\bBasic\s+[A-Za-z0-9+/=]{10,}\b')),
    ]
    
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
    
    def redact(self, text: str) -> str:
        """Redact all PII from text."""
        if not self.enabled:
            return text
        
        result = text
        for pii_type, pattern in self.PATTERNS:
            result = pattern.sub(f"[REDACTED:{pii_type.upper()}]", result)
        
        return result
    
    def contains_pii(self, text: str) -> list[str]:
        """Check if text contains PII, return list of PII types found."""
        found = []
        for pii_type, pattern in self.PATTERNS:
            if pattern.search(text):
                found.append(pii_type)
        return found


def display_legal_disclaimer() -> None:
    """Display legal disclaimer before scanning."""
    console.print()
    console.print("[bold red]╔══════════════════════════════════════════════════════════════╗[/bold red]")
    console.print("[bold red]║                    LEGAL DISCLAIMER                          ║[/bold red]")
    console.print("[bold red]╠══════════════════════════════════════════════════════════════╣[/bold red]")
    console.print("[bold red]║[/bold red] This tool is for AUTHORIZED SECURITY TESTING ONLY.          [bold red]║[/bold red]")
    console.print("[bold red]║[/bold red]                                                              [bold red]║[/bold red]")
    console.print("[bold red]║[/bold red] By using this tool, you confirm that:                       [bold red]║[/bold red]")
    console.print("[bold red]║[/bold red]  • You own or have written authorization to test the target [bold red]║[/bold red]")
    console.print("[bold red]║[/bold red]  • You will comply with all applicable laws                 [bold red]║[/bold red]")
    console.print("[bold red]║[/bold red]  • You will follow responsible disclosure practices         [bold red]║[/bold red]")
    console.print("[bold red]║[/bold red]                                                              [bold red]║[/bold red]")
    console.print("[bold red]║[/bold red] Unauthorized use may violate computer crime laws.           [bold red]║[/bold red]")
    console.print("[bold red]╚══════════════════════════════════════════════════════════════╝[/bold red]")
    console.print()
