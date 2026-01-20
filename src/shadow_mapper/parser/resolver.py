"""Variable resolution for tracking values through code."""

from __future__ import annotations

import re
from typing import Optional, Dict, Any

from shadow_mapper.core.config import Settings


class VariableResolver:
    """
    Resolves variable values by tracing definitions in source code.
    
    Handles:
    - Simple variable assignments
    - String concatenation
    - Object property access
    - Constant propagation
    """
    
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
        
        Args:
            identifier: Variable name to resolve
            content: Full source code content
            context_node: AST node where variable is used
            depth: Current resolution depth
            
        Returns:
            Resolved string value or None
        """
        if depth >= self.max_depth:
            return None
        
        # Check cache
        cache_key = f"{identifier}:{context_node.start_byte if context_node else 0}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        # Try to find variable declaration
        # Look for patterns like: const VAR = "value" or let VAR = "value"
        patterns = [
            # const/let/var with string
            rf'(?:const|let|var)\s+{re.escape(identifier)}\s*=\s*["\']([^"\']+)["\']',
            # Assignment with string
            rf'{re.escape(identifier)}\s*=\s*["\']([^"\']+)["\']',
            # Template literal
            rf'(?:const|let|var)\s+{re.escape(identifier)}\s*=\s*`([^`]+)`',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, content)
            if match:
                value = match.group(1)
                self._cache[cache_key] = value
                return value
        
        # Try to find object property
        # Look for: { VAR: "value" } or VAR: "value"
        prop_pattern = rf'{re.escape(identifier)}\s*:\s*["\']([^"\']+)["\']'
        match = re.search(prop_pattern, content)
        if match:
            value = match.group(1)
            self._cache[cache_key] = value
            return value
        
        return None
    
    def resolve_expression(self, node: Any, content: str, depth: int = 0) -> Optional[str]:
        """
        Resolve a complex expression (like string concatenation).
        
        Args:
            node: AST node of the expression
            content: Full source code content
            depth: Current resolution depth
            
        Returns:
            Resolved string value or None
        """
        if depth >= self.max_depth:
            return None
        
        if node.type in ("string", "template_string", "string_literal"):
            # Direct string
            return content[node.start_byte:node.end_byte].strip("'\"`")
        
        elif node.type == "identifier":
            # Variable reference
            var_name = content[node.start_byte:node.end_byte]
            return self.resolve(var_name, content, node, depth + 1)
        
        elif node.type == "binary_expression":
            # String concatenation (a + b)
            left = None
            right = None
            operator = None
            
            for child in node.children:
                if child.type in ("string", "template_string", "identifier", "binary_expression"):
                    if left is None:
                        left = self.resolve_expression(child, content, depth + 1)
                    else:
                        right = self.resolve_expression(child, content, depth + 1)
                elif child.type == "+":
                    operator = "+"
            
            if operator == "+" and left is not None and right is not None:
                return left + right
            elif left is not None:
                return left
        
        elif node.type == "template_literal":
            # Template literal with interpolation
            parts = []
            for child in node.children:
                if child.type == "string_fragment":
                    parts.append(content[child.start_byte:child.end_byte])
                elif child.type == "template_substitution":
                    # Try to resolve the interpolated expression
                    for subchild in child.children:
                        if subchild.type == "identifier":
                            resolved = self.resolve(
                                content[subchild.start_byte:subchild.end_byte],
                                content,
                                subchild,
                                depth + 1,
                            )
                            if resolved:
                                parts.append(resolved)
                            else:
                                parts.append("${...}")  # Placeholder for unresolved
            return "".join(parts) if parts else None
        
        elif node.type == "member_expression":
            # Object property access: obj.prop or obj["prop"]
            parts = []
            for child in node.children:
                if child.type == "identifier":
                    parts.append(content[child.start_byte:child.end_byte])
                elif child.type == "property_identifier":
                    parts.append(content[child.start_byte:child.end_byte])
            
            if len(parts) >= 2:
                # Try to find object definition
                obj_name = parts[0]
                prop_name = parts[1]
                
                # Look for object literal definition
                obj_pattern = rf'{re.escape(obj_name)}\s*=\s*\{{[^}}]*{re.escape(prop_name)}\s*:\s*["\']([^"\']+)["\'][^}}]*\}}'
                match = re.search(obj_pattern, content, re.DOTALL)
                if match:
                    return match.group(1)
        
        return None
    
    def clear_cache(self) -> None:
        """Clear the resolution cache."""
        self._cache.clear()


class ConstantPropagator:
    """
    Propagates constant values through the code.
    
    Tracks assignments and updates values as code flows.
    """
    
    def __init__(self):
        self.constants: Dict[str, str] = {}
    
    def track_assignment(self, var_name: str, value: str) -> None:
        """Track a variable assignment."""
        self.constants[var_name] = value
    
    def get_value(self, var_name: str) -> Optional[str]:
        """Get the current value of a variable."""
        return self.constants.get(var_name)
    
    def substitute(self, template: str) -> str:
        """Substitute known variables in a template string."""
        result = template
        
        for var_name, value in self.constants.items():
            # Replace ${var} style
            result = result.replace(f"${{{var_name}}}", value)
            # Replace {var} style (Python f-string like)
            result = result.replace(f"{{{var_name}}}", value)
        
        return result
