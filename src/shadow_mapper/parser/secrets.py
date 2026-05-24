"""Secret detection in source code using AST analysis."""

from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any

from shadow_mapper.core.config import Settings
from shadow_mapper.core.models import Secret, Severity, SourceLocation


# Known fake/placeholder values — skip these
KNOWN_FAKE_VALUES = {
    "your-api-key-here", "xxxxxxxxxxxx", "placeholder",
    "changeme", "example_key", "your_secret_key",
    "insert_key_here", "your_token_here", "xxxxxxxx",
    "undefined", "null", "true", "false", "example",
    "test", "sample", "dummy", "fake", "replace_me",
    "api_key_here", "secret_here", "token_here",
}

# Files to skip — usually contain example values
SKIP_FILE_PATTERNS = [
    ".env.example", ".env.sample", ".env.template",
    "README", "CHANGELOG", "CONTRIBUTING", "LICENSE",
    "*.example.*", "*.sample.*", "*.test.*", "*.spec.*",
]


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy — high entropy = likely real key."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


class SecretDetector:
    """
    Detects hardcoded secrets in source code using AST analysis.
    Improved version with:
    - Entropy-based filtering to reduce false positives
    - process.env detection (skip — not a real secret)
    - Known fake value allowlist
    - File pattern skipping
    """

    SECRET_PATTERNS = [
        {
            "name": "aws_access_key",
            "pattern": re.compile(r'AKIA[0-9A-Z]{16}'),
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
            "name": "stripe_live_key",
            "pattern": re.compile(r'sk_live_[A-Za-z0-9]{24,}'),
            "severity": Severity.CRITICAL,
        },
        {
            "name": "stripe_test_key",
            "pattern": re.compile(r'sk_test_[A-Za-z0-9]{24,}'),
            "severity": Severity.HIGH,
        },
        {
            "name": "stripe_publishable",
            "pattern": re.compile(r'pk_(?:live|test)_[A-Za-z0-9]{24,}'),
            "severity": Severity.MEDIUM,
        },
        {
            "name": "slack_token",
            "pattern": re.compile(r'xox[baprs]-[0-9A-Za-z-]{10,}'),
            "severity": Severity.HIGH,
        },
        {
            "name": "slack_webhook",
            "pattern": re.compile(
                r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+'
            ),
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
            "name": "sendgrid_key",
            "pattern": re.compile(r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'),
            "severity": Severity.CRITICAL,
        },
        {
            "name": "jwt_token",
            "pattern": re.compile(
                r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
            ),
            "severity": Severity.HIGH,
        },
        {
            "name": "private_key",
            "pattern": re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'),
            "severity": Severity.CRITICAL,
        },
        {
            "name": "database_url",
            "pattern": re.compile(
                r'(?:mysql|postgres|mongodb|redis)://[^\s"\'`]+'
            ),
            "severity": Severity.CRITICAL,
        },
        {
            "name": "generic_api_key",
            "pattern": re.compile(r'[A-Za-z0-9_-]{32,}'),
            "var_pattern": re.compile(
                r'(?:api[_-]?key|apikey|api[_-]?secret)', re.IGNORECASE
            ),
            "severity": Severity.MEDIUM,
            "min_entropy": 3.5,
        },
        {
            "name": "generic_secret",
            "pattern": re.compile(r'.{16,}'),
            "var_pattern": re.compile(
                r'(?:secret|password|passwd|pwd|token|auth)', re.IGNORECASE
            ),
            "severity": Severity.MEDIUM,
            "min_entropy": 3.8,
        },
    ]

    SECRET_VAR_PATTERNS = [
        re.compile(r'api[_-]?key', re.IGNORECASE),
        re.compile(r'api[_-]?secret', re.IGNORECASE),
        re.compile(r'auth[_-]?token', re.IGNORECASE),
        re.compile(r'access[_-]?token', re.IGNORECASE),
        re.compile(r'secret[_-]?key', re.IGNORECASE),
        re.compile(r'private[_-]?key', re.IGNORECASE),
        re.compile(r'password', re.IGNORECASE),
        re.compile(r'passwd', re.IGNORECASE),
    ]

    def __init__(self, settings: Settings):
        self.settings = settings
        # Merge config allowlist with built-in
        self._allowlist = KNOWN_FAKE_VALUES | {
            v.lower() for v in getattr(settings.parser, "secret_allowlist", [])
        }

    def should_skip_file(self, path: Path) -> bool:
        """Skip files that typically contain example/fake values."""
        name = path.name.lower()
        for pattern in SKIP_FILE_PATTERNS:
            if re.search(pattern.replace("*", ".*").lower(), name):
                return True
        return False

    def _is_env_variable(self, value: str) -> bool:
        """Check if value is a process.env reference — not a real secret."""
        env_patterns = [
            "process.env.",
            "${",
            "os.environ",
            "os.getenv",
            "getenv(",
        ]
        return any(p in value for p in env_patterns)

    def _is_fake_value(self, value: str) -> bool:
        """Check if value is a known fake/placeholder."""
        return value.lower().strip("'\"`") in self._allowlist

    def _passes_entropy_check(self, value: str, min_entropy: float = 3.5) -> bool:
        """Check if value has enough entropy to be a real secret."""
        return calculate_entropy(value) >= min_entropy

    def scan(self, tree: Any, content: str, file_path: Path) -> list[Secret]:
        """Scan parsed AST for hardcoded secrets."""
        if self.should_skip_file(file_path):
            return []

        secrets = []

        def walk(node: Any):
            yield node
            for child in node.children:
                yield from walk(child)

        for node in walk(tree.root_node):
            if node.type == "variable_declarator":
                secret = self._check_variable_declaration(node, content, file_path)
                if secret:
                    secrets.append(secret)
            elif node.type == "assignment_expression":
                secret = self._check_assignment(node, content, file_path)
                if secret:
                    secrets.append(secret)
            elif node.type in ("property", "pair", "key_value"):
                secret = self._check_property(node, content, file_path)
                if secret:
                    secrets.append(secret)

        return secrets

    def _check_variable_declaration(
        self, node: Any, content: str, file_path: Path
    ) -> Secret | None:
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
        self, node: Any, content: str, file_path: Path
    ) -> Secret | None:
        left = None
        right = None
        for child in node.children:
            if child.type == "identifier" and left is None:
                left = content[child.start_byte:child.end_byte]
            elif child.type == "member_expression" and left is None:
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
        self, node: Any, content: str, file_path: Path
    ) -> Secret | None:
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
        self, var_name: str, value: str, node: Any, file_path: Path
    ) -> Secret | None:
        # Skip short values
        if len(value) < 8:
            return None

        # Skip env variables — not hardcoded
        if self._is_env_variable(value):
            return None

        # Skip known fake values
        if self._is_fake_value(value):
            return None

        is_secret_var = any(p.search(var_name) for p in self.SECRET_VAR_PATTERNS)

        for pattern_info in self.SECRET_PATTERNS:
            pattern = pattern_info["pattern"]
            var_pattern = pattern_info.get("var_pattern")
            min_entropy = pattern_info.get("min_entropy", 0.0)

            if var_pattern and not var_pattern.search(var_name):
                continue

            if pattern.search(value):
                # Entropy check for generic patterns
                if min_entropy > 0 and not self._passes_entropy_check(value, min_entropy):
                    continue

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

        # Generic detection based on var name + entropy
        if is_secret_var and len(value) >= 16 and self._passes_entropy_check(value, 3.0):
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
