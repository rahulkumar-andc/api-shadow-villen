"""Response classification and zombie API detection heuristics."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

import httpx


@dataclass
class ResponseClassification:
    """Classification of an HTTP response."""
    
    category: str  # "active", "protected", "dead", "error", "vulnerable"
    confidence: float  # 0.0 to 1.0
    has_stack_trace: bool = False
    has_cors_issue: bool = False
    is_json_api: bool = False
    is_legacy: bool = False
    notes: list[str] = None
    
    def __post_init__(self):
        if self.notes is None:
            self.notes = []


@dataclass
class ZombieInfo:
    """Information about zombie API indicators."""
    
    is_deprecated: bool = False
    deprecation_date: Optional[datetime] = None
    sunset_date: Optional[datetime] = None
    version_indicators: list[str] = None
    age_indicators: list[str] = None
    
    def __post_init__(self):
        if self.version_indicators is None:
            self.version_indicators = []
        if self.age_indicators is None:
            self.age_indicators = []


class ResponseClassifier:
    """
    Classifies HTTP responses to determine endpoint status and potential issues.
    """
    
    # Stack trace patterns for various languages
    STACK_TRACE_PATTERNS = [
        re.compile(r'Traceback \(most recent call last\)', re.IGNORECASE),
        re.compile(r'at [A-Za-z0-9_.$]+\([^)]*\)', re.IGNORECASE),  # Java/JS stack
        re.compile(r'File "[^"]+", line \d+', re.IGNORECASE),  # Python
        re.compile(r'#\d+ [^\n]+\n\s+at ', re.IGNORECASE),  # PHP
        re.compile(r'goroutine \d+ \[', re.IGNORECASE),  # Go
        re.compile(r'panic:', re.IGNORECASE),  # Go panic
        re.compile(r'Exception in thread', re.IGNORECASE),  # Java
        re.compile(r'System\..*Exception:', re.IGNORECASE),  # .NET
    ]
    
    # Sensitive error message patterns
    SENSITIVE_ERROR_PATTERNS = [
        re.compile(r'sql.*error|mysql.*error|postgres.*error', re.IGNORECASE),
        re.compile(r'mongodb.*error|redis.*error', re.IGNORECASE),
        re.compile(r'connection refused|connection reset', re.IGNORECASE),
        re.compile(r'permission denied|access denied', re.IGNORECASE),
        re.compile(r'internal server error', re.IGNORECASE),
        re.compile(r'null pointer|undefined is not', re.IGNORECASE),
    ]
    
    def classify(self, response: httpx.Response) -> ResponseClassification:
        """
        Classify an HTTP response.
        
        Args:
            response: httpx Response object
            
        Returns:
            ResponseClassification with category and indicators
        """
        status = response.status_code
        content_type = response.headers.get("content-type", "").lower()
        
        # Get response text for analysis
        try:
            body = response.text[:10000]  # Limit to first 10KB
        except Exception:
            body = ""
        
        classification = ResponseClassification(
            category="unknown",
            confidence=1.0,
            is_json_api="application/json" in content_type,
        )
        
        # Classify by status code
        if status == 200:
            classification.category = "active"
        elif status == 201:
            classification.category = "active"
            classification.notes.append("State-changing endpoint (201 Created)")
        elif status == 204:
            classification.category = "active"
            classification.notes.append("No content response")
        elif status == 301 or status == 302:
            classification.category = "redirect"
        elif status == 400:
            classification.category = "active"
            classification.notes.append("Bad request - endpoint exists but rejected input")
        elif status == 401:
            classification.category = "protected"
            classification.notes.append("Requires authentication")
        elif status == 403:
            classification.category = "protected"
            classification.notes.append("Forbidden - ACL or WAF block")
        elif status == 404:
            classification.category = "dead"
        elif status == 405:
            classification.category = "active"
            classification.notes.append("Method not allowed - try different HTTP verb")
        elif status == 429:
            classification.category = "protected"
            classification.notes.append("Rate limited")
        elif status >= 500:
            classification.category = "error"
            classification.notes.append(f"Server error ({status})")
        
        # Check for stack traces
        for pattern in self.STACK_TRACE_PATTERNS:
            if pattern.search(body):
                classification.has_stack_trace = True
                classification.category = "vulnerable"
                classification.notes.append("Exposes stack trace")
                break
        
        # Check for sensitive errors
        for pattern in self.SENSITIVE_ERROR_PATTERNS:
            if pattern.search(body):
                classification.notes.append("Contains sensitive error message")
                break
        
        # Check CORS headers
        cors_origin = response.headers.get("access-control-allow-origin", "")
        if cors_origin == "*":
            classification.has_cors_issue = True
            classification.notes.append("Wildcard CORS - potential security issue")
        
        # Check for legacy indicators
        if "text/xml" in content_type and classification.is_json_api is False:
            classification.is_legacy = True
            classification.notes.append("XML response in potentially JSON-first API")
        
        return classification


class ZombieDetector:
    """
    Detects indicators that an endpoint might be a zombie (deprecated but active).
    """
    
    # Date parsing patterns
    DATE_PATTERNS = [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d",
        "%a, %d %b %Y %H:%M:%S %Z",
    ]
    
    def detect(self, response: httpx.Response) -> ZombieInfo:
        """
        Detect zombie API indicators in a response.
        
        Args:
            response: httpx Response object
            
        Returns:
            ZombieInfo with deprecation indicators
        """
        info = ZombieInfo()
        
        # Check Deprecation header (IETF draft standard)
        deprecation = response.headers.get("deprecation")
        if deprecation:
            info.is_deprecated = True
            info.deprecation_date = self._parse_date(deprecation)
        
        # Check Sunset header (RFC 8594)
        sunset = response.headers.get("sunset")
        if sunset:
            info.is_deprecated = True
            info.sunset_date = self._parse_date(sunset)
        
        # Check for deprecation in Link header
        link_header = response.headers.get("link", "")
        if 'rel="sunset"' in link_header or 'rel="deprecation"' in link_header:
            info.is_deprecated = True
        
        # Check for X-Deprecated header (non-standard but common)
        if response.headers.get("x-deprecated"):
            info.is_deprecated = True
        
        # Check Warning header
        warning = response.headers.get("warning", "")
        if "deprecated" in warning.lower():
            info.is_deprecated = True
            info.age_indicators.append(f"Warning header: {warning}")
        
        # Check response body for deprecation notices
        try:
            body = response.text[:5000].lower()
            
            deprecation_keywords = [
                "deprecated",
                "this api is deprecated",
                "will be removed",
                "end of life",
                "use v2 instead",
                "use v3 instead",
                "legacy",
                "obsolete",
            ]
            
            for keyword in deprecation_keywords:
                if keyword in body:
                    info.age_indicators.append(f"Body contains: '{keyword}'")
                    break
                    
        except Exception:
            pass
        
        # Check for old copyright dates
        try:
            body = response.text[:10000]
            import re
            
            copyright_pattern = re.compile(r'copyright\s*(?:©|\(c\))?\s*(\d{4})', re.IGNORECASE)
            match = copyright_pattern.search(body)
            if match:
                year = int(match.group(1))
                current_year = datetime.now().year
                if current_year - year >= 3:
                    info.age_indicators.append(f"Old copyright year: {year}")
                    
        except Exception:
            pass
        
        # Check Server header for old versions
        server = response.headers.get("server", "")
        old_server_patterns = [
            (r'Apache/1\.', "Apache 1.x"),
            (r'nginx/0\.', "nginx 0.x"),
            (r'PHP/5\.[0-4]', "PHP 5.0-5.4"),
            (r'Python/2\.', "Python 2.x"),
        ]
        
        for pattern, name in old_server_patterns:
            if re.search(pattern, server):
                info.age_indicators.append(f"Old server version: {name}")
                break
        
        return info
    
    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """Parse a date string in various formats."""
        if not date_str:
            return None
        
        # Handle special values
        if date_str.lower() == "true":
            return None
        
        for pattern in self.DATE_PATTERNS:
            try:
                return datetime.strptime(date_str, pattern)
            except ValueError:
                continue
        
        return None
