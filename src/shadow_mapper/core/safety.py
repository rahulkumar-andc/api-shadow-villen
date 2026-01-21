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


class URLValidationError(ScopeViolationError):
    """Raised when a URL fails strict validation (fail-closed)."""
    pass


class ScopeEnforcer:
    """Enforces scanning boundaries to prevent unauthorized access.
    
    Features:
    - Fail-closed: Any URL that fails validation is rejected
    - Strict URL parsing with explicit scheme/netloc requirements
    - SSRF protection (internal IP ranges, cloud metadata)
    - Optional IP address blocking
    - Audit logging for rejected URLs
    """
    
    # Valid URL schemes
    ALLOWED_SCHEMES = {"http", "https"}
    
    # IP address pattern for optional blocking
    IP_PATTERN = re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )
    
    # SSRF Protection: Internal/Private IP ranges (RFC 1918 + others)
    SSRF_BLOCKED_RANGES = [
        # Private IPv4 ranges
        re.compile(r'^10\.'),                           # 10.0.0.0/8
        re.compile(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.'),  # 172.16.0.0/12
        re.compile(r'^192\.168\.'),                     # 192.168.0.0/16
        # Loopback
        re.compile(r'^127\.'),                          # 127.0.0.0/8
        # Link-local
        re.compile(r'^169\.254\.'),                     # 169.254.0.0/16
        # Cloud metadata endpoints
        re.compile(r'^169\.254\.169\.254$'),            # AWS/GCP metadata
        re.compile(r'^metadata\.google\.internal$'),    # GCP metadata
        re.compile(r'^100\.100\.100\.200$'),            # Alibaba metadata
        # Carrier-grade NAT
        re.compile(r'^100\.(6[4-9]|[7-9][0-9]|1[0-2][0-7])\.'),  # 100.64.0.0/10
    ]
    
    # SSRF: Blocked hostnames
    SSRF_BLOCKED_HOSTNAMES = {
        'localhost',
        'localhost.localdomain',
        'metadata.google.internal',
        'metadata',
        '169.254.169.254',
        'instance-data',
    }
    
    def __init__(
        self,
        settings: ScopeSettings,
        allow_ip_addresses: bool = False,
        strict_mode: bool = True,
        ssrf_protection: bool = True,
    ):
        """Initialize ScopeEnforcer.
        
        Args:
            settings: Scope configuration
            allow_ip_addresses: Whether to allow IP addresses as hosts
            strict_mode: If True, raise URLValidationError for malformed URLs
            ssrf_protection: If True, block internal IPs and cloud metadata
        """
        self.settings = settings
        self.allow_ip_addresses = allow_ip_addresses
        self.strict_mode = strict_mode
        self.ssrf_protection = ssrf_protection
        self._allowed_patterns = self._compile_patterns(settings.allowed_domains)
        self._blocked_patterns = self._compile_patterns(settings.blocked_domains)
        self._rejected_urls: list[tuple[str, str]] = []  # (url, reason) for audit
    
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
        return fnmatch.fnmatch(domain.lower(), pattern)
    
    def _validate_url_strict(self, url: str) -> tuple[bool, str, str]:
        """Strictly validate URL format.
        
        Returns:
            Tuple of (is_valid, domain, error_reason)
        """
        if not url:
            return False, "", "Empty URL"
        
        try:
            parsed = urlparse(url)
        except Exception as e:
            return False, "", f"URL parsing failed: {e}"
        
        # Require valid scheme
        if not parsed.scheme:
            return False, "", "Missing URL scheme (http/https required)"
        
        if parsed.scheme.lower() not in self.ALLOWED_SCHEMES:
            return False, "", f"Invalid scheme '{parsed.scheme}', must be http/https"
        
        # Require non-empty netloc (domain)
        if not parsed.netloc:
            return False, "", "Missing domain/netloc in URL"
        
        domain = parsed.netloc.lower()
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Check for embedded credentials (security risk)
        if '@' in parsed.netloc:
            return False, domain, "URL contains embedded credentials (user:pass@host)"
        
        # Check for IP addresses if not allowed
        if not self.allow_ip_addresses and self.IP_PATTERN.match(domain):
            return False, domain, "IP addresses are not allowed, use domain names"
        
        # Reject localhost in production-like checks
        if domain in ('localhost', '127.0.0.1', '0.0.0.0', '::1'):
            return False, domain, "Localhost targets are not allowed"
        
        # SSRF Protection: Block internal IPs and cloud metadata endpoints
        # Note: Only block internal IPs if allow_ip_addresses is False
        if self.ssrf_protection:
            # Check blocked hostnames (always block these regardless of IP setting)
            if domain in self.SSRF_BLOCKED_HOSTNAMES:
                return False, domain, f"SSRF protection: Blocked hostname '{domain}'"
            
            # Check blocked IP ranges (only if IPs are not explicitly allowed)
            if not self.allow_ip_addresses:
                for pattern in self.SSRF_BLOCKED_RANGES:
                    if pattern.match(domain):
                        return False, domain, f"SSRF protection: Internal/private IP range blocked"
        
        return True, domain, ""
    
    def _log_rejection(self, url: str, reason: str) -> None:
        """Log URL rejection for audit purposes."""
        self._rejected_urls.append((url, reason))
        console.print(f"[yellow]URL rejected: {url} - {reason}[/yellow]")
    
    def get_rejection_log(self) -> list[tuple[str, str]]:
        """Get list of all rejected URLs with reasons."""
        return self._rejected_urls.copy()
    
    def is_allowed(self, url: str) -> bool:
        """Check if a URL is within the allowed scope.
        
        Uses fail-closed validation - malformed URLs return False.
        """
        # Strict validation
        is_valid, domain, error_reason = self._validate_url_strict(url)
        
        if not is_valid:
            self._log_rejection(url, error_reason)
            return False
        
        # Check blocked first (blocklist takes precedence)
        for pattern in self._blocked_patterns:
            if self._matches_pattern(domain, pattern):
                self._log_rejection(url, f"Matched blocked pattern: {pattern}")
                return False
        
        # If no allowed patterns specified, allow all (except blocked)
        if not self._allowed_patterns:
            return True
        
        # Check allowed patterns
        for pattern in self._allowed_patterns:
            if self._matches_pattern(domain, pattern):
                return True
        
        self._log_rejection(url, "Not in allowed domains list")
        return False
    
    def validate(self, url: str) -> None:
        """Validate URL and raise if out of scope or malformed.
        
        Raises:
            URLValidationError: If URL is malformed (fail-closed)
            ScopeViolationError: If URL is valid but out of scope
        """
        # Strict validation first
        is_valid, domain, error_reason = self._validate_url_strict(url)
        
        if not is_valid:
            if self.strict_mode:
                raise URLValidationError(
                    f"URL validation failed for '{url}': {error_reason}"
                )
            else:
                raise ScopeViolationError(
                    f"Target '{url}' failed validation: {error_reason}"
                )
        
        # Then check scope
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
    """Token bucket rate limiter with adaptive backoff and response caching.
    
    Features:
    - Token bucket algorithm for rate limiting
    - Exponential backoff on 429 responses
    - Caches rate-limited endpoints to avoid re-hitting
    """
    
    settings: RateLimitSettings
    tokens: float = field(init=False)
    last_update: float = field(init=False)
    backoff_until: float = field(init=False, default=0.0)
    current_backoff: float = field(init=False, default=1.0)
    # Rate limit cache: {endpoint_key: (blocked_until, retry_after)}
    _rate_limit_cache: dict[str, tuple[float, int]] = field(init=False, default_factory=dict)
    
    # Default cache TTL for rate-limited endpoints (5 minutes)
    RATE_LIMIT_CACHE_TTL = 300
    
    def __post_init__(self):
        self.tokens = float(self.settings.burst)
        self.last_update = time.monotonic()
        self._rate_limit_cache = {}
    
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
    
    def get_endpoint_key(self, url: str, method: str = "GET") -> str:
        """Generate a cache key for an endpoint."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return f"{method}:{parsed.netloc}{parsed.path}"
    
    def is_rate_limited(self, url: str, method: str = "GET") -> tuple[bool, int]:
        """Check if an endpoint is currently rate-limited.
        
        Returns:
            Tuple of (is_limited, retry_after_seconds)
        """
        key = self.get_endpoint_key(url, method)
        if key in self._rate_limit_cache:
            blocked_until, retry_after = self._rate_limit_cache[key]
            if time.monotonic() < blocked_until:
                remaining = int(blocked_until - time.monotonic())
                return True, remaining
            else:
                # Cache expired, remove entry
                del self._rate_limit_cache[key]
        return False, 0
    
    def cache_rate_limit(
        self,
        url: str,
        method: str = "GET",
        retry_after: int = None,
    ) -> None:
        """Cache a rate-limited endpoint.
        
        Args:
            url: The endpoint URL
            method: HTTP method
            retry_after: Retry-After header value (if available)
        """
        key = self.get_endpoint_key(url, method)
        ttl = retry_after if retry_after else self.RATE_LIMIT_CACHE_TTL
        blocked_until = time.monotonic() + ttl
        self._rate_limit_cache[key] = (blocked_until, ttl)
        console.print(
            f"[yellow]Cached rate limit for {method} {key} ({ttl}s)[/yellow]"
        )
    
    def get_cached_count(self) -> int:
        """Get number of endpoints currently cached as rate-limited."""
        now = time.monotonic()
        # Cleanup expired entries while counting
        expired = [k for k, (t, _) in self._rate_limit_cache.items() if t <= now]
        for k in expired:
            del self._rate_limit_cache[k]
        return len(self._rate_limit_cache)
    
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
    """Redacts personally identifiable information from text.
    
    Features:
    - Luhn algorithm validation for credit card numbers
    - UUID-aware patterns to avoid false positives
    - Entropy-based API key detection
    """
    
    # UUID pattern to exclude from credit card matches
    UUID_PATTERN = re.compile(
        r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        re.I
    )
    
    # Pre-compiled raw patterns (before validation)
    RAW_PATTERNS: list[tuple[str, Pattern[str]]] = [
        ("email", re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')),
        ("phone", re.compile(r'\b(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b')),
        ("ssn", re.compile(r'\b\d{3}-\d{2}-\d{4}\b')),
        # Credit card - preliminary pattern, validated with Luhn
        ("credit_card", re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b')),
        ("ipv4", re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')),
        # API keys - require known prefixes for better precision
        ("api_key_stripe", re.compile(r'\b(?:sk|pk)_(?:live|test)_[a-zA-Z0-9]{24,}\b')),
        ("api_key_aws", re.compile(r'\bAKIA[0-9A-Z]{16}\b')),
        ("api_key_github", re.compile(r'\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}\b')),
        ("api_key_google", re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b')),
        # Generic API key - stricter pattern with minimum length and entropy check
        ("api_key_generic", re.compile(
            r'\b(?:api[_-]?key|apikey|secret[_-]?key|auth[_-]?token|access[_-]?token)'
            r'["\'\s:=]+([a-zA-Z0-9\-_]{32,})\b',
            re.I
        )),
        ("bearer_token", re.compile(r'\bBearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b')),
        ("basic_auth", re.compile(r'\bBasic\s+[A-Za-z0-9+/=]{20,}\b')),
        # Private keys
        ("private_key", re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----')),
    ]
    
    def __init__(self, enabled: bool = True, validate_checksums: bool = True):
        """Initialize PIIRedactor.
        
        Args:
            enabled: Whether redaction is enabled
            validate_checksums: Whether to validate checksums (Luhn for CC)
        """
        self.enabled = enabled
        self.validate_checksums = validate_checksums
    
    @staticmethod
    def luhn_check(number: str) -> bool:
        """Validate a number using the Luhn algorithm (credit cards, etc.).
        
        Args:
            number: String containing digits to validate
            
        Returns:
            True if the number passes Luhn validation
        """
        # Extract only digits
        digits = [int(d) for d in number if d.isdigit()]
        
        # Credit cards are typically 13-19 digits
        if len(digits) < 13 or len(digits) > 19:
            return False
        
        # Luhn algorithm
        checksum = 0
        for i, digit in enumerate(reversed(digits)):
            if i % 2 == 1:  # Double every second digit from right
                digit *= 2
                if digit > 9:
                    digit -= 9
            checksum += digit
        
        return checksum % 10 == 0
    
    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Calculate Shannon entropy of a string.
        
        Higher entropy suggests more randomness (likely a key/token).
        """
        import math
        if not text:
            return 0.0
        
        # Count character frequencies
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate entropy
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            prob = count / length
            entropy -= prob * math.log2(prob)
        
        return entropy
    
    def _is_uuid(self, text: str) -> bool:
        """Check if text is or contains a UUID pattern."""
        return bool(self.UUID_PATTERN.search(text))
    
    def _validate_credit_card(self, match: str) -> bool:
        """Validate a potential credit card number.
        
        Returns False for UUIDs and numbers failing Luhn check.
        """
        # Skip if it looks like a UUID
        if self._is_uuid(match):
            return False
        
        # Skip if checksum validation is disabled
        if not self.validate_checksums:
            return True
        
        # Validate with Luhn algorithm
        return self.luhn_check(match)
    
    def _validate_api_key(self, key: str) -> bool:
        """Validate a potential API key based on entropy.
        
        Real API keys typically have high entropy (randomness).
        """
        # Minimum entropy threshold for API keys
        MIN_ENTROPY = 3.5
        return self.calculate_entropy(key) >= MIN_ENTROPY
    
    def redact(self, text: str) -> str:
        """Redact all PII from text.
        
        Uses validation to reduce false positives.
        """
        if not self.enabled:
            return text
        
        result = text
        
        for pii_type, pattern in self.RAW_PATTERNS:
            if pii_type == "credit_card":
                # Use callback to validate each match
                def cc_replacer(match):
                    if self._validate_credit_card(match.group(0)):
                        return "[REDACTED:CREDIT_CARD]"
                    return match.group(0)
                result = pattern.sub(cc_replacer, result)
            elif pii_type == "api_key_generic":
                # Extract the actual key from the match and validate entropy
                def key_replacer(match):
                    if match.group(1) and self._validate_api_key(match.group(1)):
                        return match.group(0).replace(match.group(1), "[REDACTED:API_KEY]")
                    return match.group(0)
                result = pattern.sub(key_replacer, result)
            else:
                result = pattern.sub(f"[REDACTED:{pii_type.upper()}]", result)
        
        return result
    
    def contains_pii(self, text: str) -> list[str]:
        """Check if text contains PII, return list of PII types found.
        
        Uses validation to reduce false positives.
        """
        found = []
        
        for pii_type, pattern in self.RAW_PATTERNS:
            matches = pattern.findall(text)
            
            if pii_type == "credit_card":
                # Validate each credit card match
                for match in pattern.finditer(text):
                    if self._validate_credit_card(match.group(0)):
                        found.append(pii_type)
                        break
            elif pii_type == "api_key_generic":
                # Validate entropy for generic API keys
                for match in pattern.finditer(text):
                    if match.group(1) and self._validate_api_key(match.group(1)):
                        found.append(pii_type)
                        break
            elif matches:
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
