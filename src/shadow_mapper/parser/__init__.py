"""Parser module - Static analysis using Tree-sitter AST."""

from shadow_mapper.parser.engine import ParserEngine
from shadow_mapper.parser.resolver import VariableResolver
from shadow_mapper.parser.secrets import SecretDetector

__all__ = [
    "ParserEngine",
    "VariableResolver",
    "SecretDetector",
]
