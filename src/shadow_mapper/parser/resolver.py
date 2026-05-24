"""Variable resolution for tracking values through code."""

from __future__ import annotations

import re
from typing import Optional, Dict, Any

from shadow_mapper.core.config import Settings


class VariableResolver:
    """
    Resolves variable values by tracing definitions in source code.

    Handles:
    - Simple variable assignments (const x = "/api/v1")
    - String concatenation  (BASE + "/users")
    - Template literals     (`${BASE}/users`)
    - Object property access (config.baseUrl)
    - Constant propagation
    - process.env detection (returns None — not a real value)
    """

    # process.env / os.environ patterns — skip these
    ENV_PATTERNS = re.compile(
        r'process\.env\.|os\.environ|os\.getenv|getenv\(', re.IGNORECASE
    )

    def __init__(self, settings: Settings):
        self.settings = settings
        self.max_depth = settings.parser.max_resolution_depth
        self._cache: Dict[str, str] = {}

    def resolve(
        self,
        identifier: str,
        content: str,
        context_node: Any,
        depth: int = 0,
    ) -> Optional[str]:
        """
        Attempt to resolve a variable to its string value.

        Returns None for env variables, unresolved vars, or depth exceeded.
        """
        if depth >= self.max_depth:
            return None

        # Skip env-like names
        if identifier.lower() in ("process", "env", "undefined", "null", "window"):
            return None

        cache_key = f"{identifier}:{getattr(context_node, 'start_byte', 0)}"
        if cache_key in self._cache:
            return self._cache.get(cache_key)

        patterns = [
            # const/let/var with double or single quotes
            rf'(?:const|let|var)\s+{re.escape(identifier)}\s*=\s*"([^"]+)"',
            rf"(?:const|let|var)\s+{re.escape(identifier)}\s*=\s*'([^']+)'",
            # Template literal (simple, no interpolation)
            rf'(?:const|let|var)\s+{re.escape(identifier)}\s*=\s*`([^`${{}}]+)`',
            # Plain assignment
            rf'{re.escape(identifier)}\s*=\s*"([^"]+)"',
            rf"{re.escape(identifier)}\s*=\s*'([^']+)'",
        ]

        for pattern in patterns:
            match = re.search(pattern, content)
            if match:
                value = match.group(1)
                # Skip if the value references an env variable
                if self.ENV_PATTERNS.search(value):
                    return None
                self._cache[cache_key] = value
                return value

        # Object property: { identifier: "value" }
        prop_pattern = rf'(?:^|[,{{])\s*["\']?{re.escape(identifier)}["\']?\s*:\s*["\']([^"\']+)["\']'
        match = re.search(prop_pattern, content, re.MULTILINE)
        if match:
            value = match.group(1)
            if not self.ENV_PATTERNS.search(value):
                self._cache[cache_key] = value
                return value

        return None

    def resolve_expression(
        self, node: Any, content: str, depth: int = 0
    ) -> Optional[str]:
        """
        Resolve a complex expression to a string.

        Handles: string literals, identifiers, binary (+) expressions,
        template literals with ${} interpolation.
        """
        if depth >= self.max_depth:
            return None

        ntype = node.type

        # Direct string
        if ntype in ("string", "template_string", "string_literal"):
            raw = content[node.start_byte:node.end_byte].strip("'\"`")
            if self.ENV_PATTERNS.search(raw):
                return None
            return raw

        # Variable reference
        if ntype == "identifier":
            name = content[node.start_byte:node.end_byte]
            return self.resolve(name, content, node, depth + 1)

        # Binary expression: a + b
        if ntype == "binary_expression":
            parts = []
            op_found = False
            for child in node.children:
                if child.type == "+":
                    op_found = True
                elif child.type not in ("(", ")"):
                    val = self.resolve_expression(child, content, depth + 1)
                    if val is not None:
                        parts.append(val)
                    else:
                        parts.append("{?}")
            if op_found and parts:
                result = "".join(parts)
                # Only return if it looks like a useful API path
                if "{?}" not in result or result.startswith("/"):
                    return result.replace("{?}", "{param}")
            return None

        # Template literal: `${BASE}/users/${id}`
        if ntype in ("template_literal", "template_string"):
            parts = []
            for child in node.children:
                if child.type == "string_fragment":
                    parts.append(content[child.start_byte:child.end_byte])
                elif child.type == "template_substitution":
                    # Try to resolve the inner expression
                    resolved = None
                    for subchild in child.children:
                        if subchild.type not in ("${", "}"):
                            resolved = self.resolve_expression(
                                subchild, content, depth + 1
                            )
                            break
                    parts.append(resolved if resolved else "{param}")
            result = "".join(parts)
            if self.ENV_PATTERNS.search(result):
                return None
            return result if result else None

        # Member expression: obj.property
        if ntype == "member_expression":
            text = content[node.start_byte:node.end_byte]
            # Skip env references
            if self.ENV_PATTERNS.search(text):
                return None
            # Try to resolve as object property
            parts = []
            for child in node.children:
                if child.type in ("identifier", "property_identifier"):
                    parts.append(content[child.start_byte:child.end_byte])
            if len(parts) >= 2:
                obj_name  = parts[0]
                prop_name = parts[1]
                obj_pattern = (
                    rf'{re.escape(obj_name)}\s*[=:]\s*\{{[^}}]*'
                    rf'["\']?{re.escape(prop_name)}["\']?\s*:\s*["\']([^"\']+)["\']'
                )
                match = re.search(obj_pattern, content, re.DOTALL)
                if match:
                    return match.group(1)
            return None

        return None

    def clear_cache(self) -> None:
        self._cache.clear()


class ConstantPropagator:
    """Propagates constant values through code."""

    def __init__(self):
        self.constants: Dict[str, str] = {}

    def track_assignment(self, var_name: str, value: str) -> None:
        self.constants[var_name] = value

    def get_value(self, var_name: str) -> Optional[str]:
        return self.constants.get(var_name)

    def substitute(self, template: str) -> str:
        result = template
        for var_name, value in self.constants.items():
            result = result.replace(f"${{{var_name}}}", value)
            result = result.replace(f"{{{var_name}}}", value)
        return result
