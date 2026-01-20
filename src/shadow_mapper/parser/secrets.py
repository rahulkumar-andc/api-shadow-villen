"""Secret detection in source code using AST analysis."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from shadow_mapper.core.config import Settings
from shadow_mapper.core.models import Secret, Severity, SourceLocation


class SecretDetector:
    """
    Detects hardcoded secrets in source code using AST and pattern matching.
    
    More accurate than regex-only approaches because it understands code context.
    """
    
    # Secret patterns with their severity
    SECRET_PATTERNS = [
        # API Keys
        {
            "name": "aws_access_key",
            "pattern": re.compile(r'AKIA[0-9A-Z]{16}'),
            "severity": Severity.CRITICAL,
        },
        {
            "name": "aws_secret_key",
            "pattern": re.compile(r'[A-Za-z0-9/+=]{40}'),
            "var_pattern": re.compile(r'aws.*secret', re.IGNORECASE),
            "severity": Severity.CRITICAL,
        },
        {
            "name": "github_token",
            "pattern": re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'),
            "severity": Severity.CRITICAL,
        },
        {
            "name": "github_pat",
            "pattern": re.compile(r'github_pat_[A-Za-z0-9_]{22,}'),
            "severity": Severity.CRITICAL,
        },
        {
            "name": "stripe_key",
            "pattern": re.compile(r'sk_(?:live|test)_[A-Za-z0-9]{24,}'),
            "severity": Severity.CRITICAL,
        },
        {
            "name": "stripe_key",
            "pattern": re.compile(r'pk_(?:live|test)_[A-Za-z0-9]{24,}'),
            "severity": Severity.HIGH,
        },
        {
            "name": "slack_token",
            "pattern": re.compile(r'xox[baprs]-[0-9A-Za-z-]{10,}'),
            "severity": Severity.HIGH,
        },
        {
            "name": "slack_webhook",
            "pattern": re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+'),
            "severity": Severity.HIGH,
        },
        {
            "name": "google_api_key",
            "pattern": re.compile(r'AIza[0-9A-Za-z_-]{35}'),
            "severity": Severity.HIGH,
        },
        {
            "name": "firebase_key",
            "pattern": re.compile(r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,}'),
            "severity": Severity.HIGH,
        },
        {
            "name": "twilio_sid",
            "pattern": re.compile(r'AC[a-z0-9]{32}'),
            "severity": Severity.HIGH,
        },
        {
            "name": "twilio_auth",
            "pattern": re.compile(r'SK[a-z0-9]{32}'),
            "severity": Severity.CRITICAL,
        },
        {
            "name": "sendgrid_key",
            "pattern": re.compile(r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'),
            "severity": Severity.CRITICAL,
        },
        {
            "name": "jwt_token",
            "pattern": re.compile(r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'),
            "severity": Severity.HIGH,
        },
        {
            "name": "private_key",
            "pattern": re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'),
            "severity": Severity.CRITICAL,
        },
        {
            "name": "database_url",
            "pattern": re.compile(r'(?:mysql|postgres|mongodb|redis)://[^\s"\']+'),
            "severity": Severity.CRITICAL,
        },
        # Generic patterns based on variable names
        {
            "name": "generic_api_key",
            "pattern": re.compile(r'[A-Za-z0-9_-]{32,}'),
            "var_pattern": re.compile(r'(?:api[_-]?key|apikey|api[_-]?secret)', re.IGNORECASE),
            "severity": Severity.MEDIUM,
        },
        {
            "name": "generic_secret",
            "pattern": re.compile(r'.{16,}'),
            "var_pattern": re.compile(r'(?:secret|password|passwd|pwd|token|auth)', re.IGNORECASE),
            "severity": Severity.MEDIUM,
        },
    ]
    
    # Variable name patterns that suggest secrets
    SECRET_VAR_PATTERNS = [
        re.compile(r'api[_-]?key', re.IGNORECASE),
        re.compile(r'api[_-]?secret', re.IGNORECASE),
        re.compile(r'auth[_-]?token', re.IGNORECASE),
        re.compile(r'access[_-]?token', re.IGNORECASE),
        re.compile(r'secret[_-]?key', re.IGNORECASE),
        re.compile(r'private[_-]?key', re.IGNORECASE),
        re.compile(r'password', re.IGNORECASE),
        re.compile(r'passwd', re.IGNORECASE),
        re.compile(r'credentials?', re.IGNORECASE),
    ]
    
    def __init__(self, settings: Settings):
        self.settings = settings
    
    def scan(self, tree: Any, content: str, file_path: Path) -> list[Secret]:
        """
        Scan parsed AST for hardcoded secrets.
        
        Args:
            tree: Parsed AST from Tree-sitter
            content: Source code content
            file_path: Path to source file
            
        Returns:
            List of detected secrets
        """
        secrets = []
        
        # Walk the AST
        def walk(node):
            yield node
            for child in node.children:
                yield from walk(child)
        
        for node in walk(tree.root_node):
            # Look for variable declarations with string values
            if node.type == "variable_declarator":
                secret = self._check_variable_declaration(node, content, file_path)
                if secret:
                    secrets.append(secret)
            
            # Look for assignments
            elif node.type == "assignment_expression":
                secret = self._check_assignment(node, content, file_path)
                if secret:
                    secrets.append(secret)
            
            # Look for object properties
            elif node.type in ("property", "pair", "key_value"):
                secret = self._check_property(node, content, file_path)
                if secret:
                    secrets.append(secret)
        
        return secrets
    
    def _check_variable_declaration(
        self,
        node: Any,
        content: str,
        file_path: Path,
    ) -> Secret | None:
        """Check a variable declaration for secrets."""
        var_name = None
        value = None
        
        for child in node.children:
            if child.type == "identifier":
                var_name = content[child.start_byte:child.end_byte]
            elif child.type in ("string", "string_literal", "template_string"):
                value = content[child.start_byte:child.end_byte].strip("'\"`")
        
        if var_name and value:
            return self._analyze_secret(var_name, value, node, file_path)
        
        return None
    
    def _check_assignment(
        self,
        node: Any,
        content: str,
        file_path: Path,
    ) -> Secret | None:
        """Check an assignment for secrets."""
        left = None
        right = None
        
        for child in node.children:
            if child.type == "identifier" and left is None:
                left = content[child.start_byte:child.end_byte]
            elif child.type == "member_expression" and left is None:
                # Handle obj.prop = value
                parts = []
                for subchild in child.children:
                    if subchild.type in ("identifier", "property_identifier"):
                        parts.append(content[subchild.start_byte:subchild.end_byte])
                left = ".".join(parts)
            elif child.type in ("string", "string_literal", "template_string"):
                right = content[child.start_byte:child.end_byte].strip("'\"`")
        
        if left and right:
            return self._analyze_secret(left, right, node, file_path)
        
        return None
    
    def _check_property(
        self,
        node: Any,
        content: str,
        file_path: Path,
    ) -> Secret | None:
        """Check an object property for secrets."""
        key = None
        value = None
        
        for child in node.children:
            if child.type in ("property_identifier", "identifier", "string"):
                if key is None:
                    key = content[child.start_byte:child.end_byte].strip("'\"")
                else:
                    value = content[child.start_byte:child.end_byte].strip("'\"")
            elif child.type in ("string_literal", "template_string"):
                value = content[child.start_byte:child.end_byte].strip("'\"`")
        
        if key and value:
            return self._analyze_secret(key, value, node, file_path)
        
        return None
    
    def _analyze_secret(
        self,
        var_name: str,
        value: str,
        node: Any,
        file_path: Path,
    ) -> Secret | None:
        """
        Analyze a variable/value pair for potential secrets.
        
        Uses both pattern matching on the value and context from the variable name.
        """
        # Skip short values (likely not secrets)
        if len(value) < 8:
            return None
        
        # Skip obvious non-secrets
        if value.lower() in ("undefined", "null", "true", "false", "example", "test", "sample"):
            return None
        
        # Check if variable name suggests a secret
        is_secret_var = any(p.search(var_name) for p in self.SECRET_VAR_PATTERNS)
        
        # Check each secret pattern
        for pattern_info in self.SECRET_PATTERNS:
            pattern = pattern_info["pattern"]
            var_pattern = pattern_info.get("var_pattern")
            
            # If pattern has a variable name requirement, check it
            if var_pattern and not var_pattern.search(var_name):
                continue
            
            # Check if value matches pattern
            if pattern.search(value):
                return Secret(
                    type=pattern_info["name"],
                    value=value,
                    source=SourceLocation(
                        file=file_path,
                        line=node.start_point[0] + 1,
                        column=node.start_point[1] + 1,
                        context=f"{var_name} = ...",
                    ),
                    severity=pattern_info["severity"],
                )
        
        # If variable name suggests secret but no pattern matched, flag it anyway
        if is_secret_var and len(value) >= 16:
            return Secret(
                type="potential_secret",
                value=value,
                source=SourceLocation(
                    file=file_path,
                    line=node.start_point[0] + 1,
                    column=node.start_point[1] + 1,
                    context=f"{var_name} = ...",
                ),
                severity=Severity.LOW,
            )
        
        return None
