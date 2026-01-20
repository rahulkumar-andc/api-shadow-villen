"""Tree-sitter based parsing engine for API endpoint extraction."""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Generator, Optional

from rich.console import Console

from shadow_mapper.core.config import Settings
from shadow_mapper.core.models import (
    Endpoint,
    HTTPMethod,
    ScanResult,
    SourceLocation,
)
from shadow_mapper.parser.resolver import VariableResolver
from shadow_mapper.parser.secrets import SecretDetector

console = Console()


class ParserEngine:
    """
    AST-based parser for extracting API endpoints from source code.
    
    Uses Tree-sitter for parsing and custom queries for endpoint extraction.
    """
    
    # HTTP client function patterns
    HTTP_CLIENT_FUNCTIONS = {
        "javascript": [
            "fetch",
            "axios",
            "request",
            "ajax",
            "http",
            "get",
            "post",
            "put",
            "delete",
            "patch",
        ],
        "typescript": [
            "fetch",
            "axios",
            "request",
            "ajax",
            "http",
            "get",
            "post",
            "put",
            "delete",
            "patch",
            "httpClient",
        ],
        "python": [
            "requests.get",
            "requests.post",
            "requests.put",
            "requests.delete",
            "requests.patch",
            "httpx.get",
            "httpx.post",
            "httpx.put",
            "httpx.delete",
            "aiohttp.get",
            "aiohttp.post",
            "urllib.request.urlopen",
        ],
    }
    
    # URL/path patterns for extraction
    URL_PATTERN = re.compile(
        r'^(?:https?://[^/]+)?(/(?:api|v\d+|graphql|rest|ws)[^\s"\'`]*)',
        re.IGNORECASE
    )
    
    API_PATH_PATTERN = re.compile(
        r'^/(?:api|v\d+|graphql|rest|auth|admin|user|public)[^\s"\'`]*',
        re.IGNORECASE
    )
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.resolver = VariableResolver(settings) if settings.parser.resolve_variables else None
        self.secret_detector = SecretDetector(settings) if settings.parser.detect_secrets else None
        self._parsers: dict[str, tuple] = {}
        self._init_parsers()
    
    def _init_parsers(self) -> None:
        """Initialize Tree-sitter parsers for configured languages."""
        try:
            import tree_sitter_javascript as ts_js
            import tree_sitter_python as ts_py
            from tree_sitter import Language, Parser
            
            # JavaScript/TypeScript parser
            if "javascript" in self.settings.parser.languages or "typescript" in self.settings.parser.languages:
                js_lang = Language(ts_js.language(), "javascript")
                js_parser = Parser()
                js_parser.set_language(js_lang)
                self._parsers["javascript"] = (js_parser, "javascript")
                self._parsers["typescript"] = (js_parser, "javascript")  # TS uses JS parser for basic parsing
            
            # Python parser
            if "python" in self.settings.parser.languages:
                py_lang = Language(ts_py.language(), "python")
                py_parser = Parser()
                py_parser.set_language(py_lang)
                self._parsers["python"] = (py_parser, "python")
                
        except ImportError as e:
            console.print(f"[yellow]Warning: Could not initialize Tree-sitter: {e}[/yellow]")
    
    def _detect_language(self, file_path: Path) -> Optional[str]:
        """Detect programming language from file extension."""
        ext_map = {
            ".js": "javascript",
            ".jsx": "javascript",
            ".mjs": "javascript",
            ".cjs": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".py": "python",
            ".pyw": "python",
        }
        return ext_map.get(file_path.suffix.lower())
    
    def parse_file(self, file_path: Path) -> ScanResult:
        """
        Parse a single file and extract endpoints.
        
        Args:
            file_path: Path to source file
            
        Returns:
            ScanResult with extracted endpoints and secrets
        """
        start_time = time.time()
        result = ScanResult(source_file=file_path)
        
        # Detect language
        language = self._detect_language(file_path)
        if not language or language not in self._parsers:
            return result
        
        # Read file
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            result.errors.append(f"Read error: {str(e)}")
            return result
        
        # Parse with Tree-sitter
        parser, lang_name = self._parsers[language]
        
        try:
            tree = parser.parse(bytes(content, "utf-8"))
            
            # Extract endpoints
            endpoints = list(self._extract_endpoints(tree, content, file_path, lang_name))
            result.endpoints.extend(endpoints)
            
            # Extract secrets
            if self.secret_detector:
                secrets = self.secret_detector.scan(tree, content, file_path)
                result.secrets.extend(secrets)
                
        except Exception as e:
            result.errors.append(f"Parse error: {str(e)}")
        
        result.parse_time_ms = (time.time() - start_time) * 1000
        return result
    
    def _extract_endpoints(
        self,
        tree,
        content: str,
        file_path: Path,
        language: str,
    ) -> Generator[Endpoint, None, None]:
        """Extract endpoints from parsed AST."""
        
        # Walk the AST looking for function calls
        def walk(node):
            yield node
            for child in node.children:
                yield from walk(child)
        
        http_functions = set(self.HTTP_CLIENT_FUNCTIONS.get(language, []))
        
        for node in walk(tree.root_node):
            # Look for call expressions
            if node.type == "call_expression":
                endpoint = self._analyze_call(node, content, file_path, http_functions)
                if endpoint:
                    yield endpoint
            
            # Look for string literals that look like API paths
            elif node.type in ("string", "template_string", "string_literal"):
                endpoint = self._analyze_string(node, content, file_path)
                if endpoint:
                    yield endpoint
    
    def _analyze_call(
        self,
        node,
        content: str,
        file_path: Path,
        http_functions: set[str],
    ) -> Optional[Endpoint]:
        """Analyze a function call for HTTP client usage."""
        
        # Get function name
        func_name = None
        method = HTTPMethod.GET
        
        for child in node.children:
            if child.type == "identifier":
                func_name = content[child.start_byte:child.end_byte]
                break
            elif child.type == "member_expression":
                # Handle object.method() calls
                parts = []
                for subchild in child.children:
                    if subchild.type == "identifier":
                        parts.append(content[subchild.start_byte:subchild.end_byte])
                    elif subchild.type == "property_identifier":
                        parts.append(content[subchild.start_byte:subchild.end_byte])
                
                if parts:
                    func_name = parts[-1]  # Use the method name
                    
                    # Detect HTTP method from function name
                    method_map = {
                        "get": HTTPMethod.GET,
                        "post": HTTPMethod.POST,
                        "put": HTTPMethod.PUT,
                        "delete": HTTPMethod.DELETE,
                        "patch": HTTPMethod.PATCH,
                    }
                    func_lower = func_name.lower()
                    if func_lower in method_map:
                        method = method_map[func_lower]
                break
        
        if not func_name or func_name.lower() not in http_functions:
            return None
        
        # Find arguments
        for child in node.children:
            if child.type == "arguments":
                # Get first argument (usually the URL)
                for arg in child.children:
                    if arg.type in ("string", "template_string", "string_literal"):
                        url = content[arg.start_byte:arg.end_byte].strip("'\"`")
                        
                        # Validate it looks like an API path
                        if self._is_api_url(url):
                            return Endpoint(
                                url=url,
                                method=method,
                                source=SourceLocation(
                                    file=file_path,
                                    line=node.start_point[0] + 1,
                                    column=node.start_point[1] + 1,
                                    context=content[node.start_byte:node.end_byte][:100],
                                ),
                            )
                    
                    elif arg.type == "identifier" and self.resolver:
                        # Try to resolve variable
                        var_name = content[arg.start_byte:arg.end_byte]
                        resolved = self.resolver.resolve(var_name, content, node)
                        
                        if resolved and self._is_api_url(resolved):
                            return Endpoint(
                                url=resolved,
                                method=method,
                                source=SourceLocation(
                                    file=file_path,
                                    line=node.start_point[0] + 1,
                                    column=node.start_point[1] + 1,
                                    context=f"{var_name} = {resolved}",
                                ),
                            )
                    
                    elif arg.type == "binary_expression" and self.resolver:
                        # Handle string concatenation
                        resolved = self.resolver.resolve_expression(arg, content)
                        
                        if resolved and self._is_api_url(resolved):
                            return Endpoint(
                                url=resolved,
                                method=method,
                                source=SourceLocation(
                                    file=file_path,
                                    line=node.start_point[0] + 1,
                                    column=node.start_point[1] + 1,
                                    context=content[arg.start_byte:arg.end_byte][:100],
                                ),
                            )
                    
                    break  # Only check first argument
        
        return None
    
    def _analyze_string(
        self,
        node,
        content: str,
        file_path: Path,
    ) -> Optional[Endpoint]:
        """Analyze a string literal for API-like paths."""
        value = content[node.start_byte:node.end_byte].strip("'\"`")
        
        # Check if it looks like an API URL
        if self._is_api_url(value):
            return Endpoint(
                url=value,
                method=HTTPMethod.GET,  # Default to GET for string literals
                source=SourceLocation(
                    file=file_path,
                    line=node.start_point[0] + 1,
                    column=node.start_point[1] + 1,
                    context=value[:100],
                ),
            )
        
        return None
    
    def _is_api_url(self, url: str) -> bool:
        """Check if a string looks like an API URL/path."""
        if not url:
            return False
        
        # Skip common non-API paths
        non_api_patterns = [
            r'\.(?:js|css|png|jpg|jpeg|gif|svg|ico|woff|ttf|eot)$',
            r'^/static/',
            r'^/assets/',
            r'^/images/',
            r'^/fonts/',
            r'^#',
            r'^mailto:',
            r'^javascript:',
        ]
        
        for pattern in non_api_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return False
        
        # Check for API patterns
        return bool(self.URL_PATTERN.match(url) or self.API_PATH_PATTERN.match(url))
    
    def parse_directory(self, directory: Path) -> list[ScanResult]:
        """
        Parse all source files in a directory.
        
        Args:
            directory: Directory to scan
            
        Returns:
            List of ScanResults for each file
        """
        results = []
        
        if not directory.exists():
            return results
        
        # Supported extensions
        extensions = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py"}
        
        # Find all source files
        source_files = []
        for ext in extensions:
            source_files.extend(directory.rglob(f"*{ext}"))
        
        console.print(f"  [dim]Found {len(source_files)} source files to parse[/dim]")
        
        for file_path in source_files:
            # Skip node_modules and similar
            if "node_modules" in str(file_path) or "__pycache__" in str(file_path):
                continue
            
            result = self.parse_file(file_path)
            
            if result.endpoints or result.secrets or result.errors:
                results.append(result)
        
        return results
