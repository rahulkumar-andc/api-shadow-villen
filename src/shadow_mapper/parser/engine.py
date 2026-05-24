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
    Uses Tree-sitter for parsing with improved pattern coverage.
    """

    # Extended HTTP client patterns — covers more frameworks
    HTTP_CLIENT_FUNCTIONS = {
        "javascript": [
            # Native
            "fetch",
            # Axios
            "axios", "get", "post", "put", "delete", "patch",
            # jQuery
            "ajax",
            # Angular HttpClient
            "http", "httpClient",
            # got, ky, superagent, needle
            "got", "ky", "superagent", "needle",
            # request (legacy)
            "request",
        ],
        "typescript": [
            "fetch", "axios", "get", "post", "put", "delete", "patch",
            "http", "httpClient", "got", "ky", "superagent",
            "request", "ajax",
        ],
        "python": [
            "get", "post", "put", "delete", "patch", "request",
            "urlopen", "open",
        ],
    }

    # Object names that indicate HTTP clients
    HTTP_CLIENT_OBJECTS = {
        "axios", "http", "https", "request", "superagent",
        "got", "ky", "needle", "fetch", "httpClient",
        "this.http", "this.httpClient", "this._http",
        "requests", "httpx", "aiohttp", "urllib",
    }

    # URL patterns
    URL_PATTERN = re.compile(
        r'^(?:https?://[^/]+)?(/(?:api|v\d+|graphql|rest|ws|auth|admin|user|public)[^\s"\'`]*)',
        re.IGNORECASE
    )

    API_PATH_PATTERN = re.compile(
        r'^/(?:api|v\d+|graphql|rest|auth|admin|user|public|internal|service|rpc)[^\s"\'`]*',
        re.IGNORECASE
    )

    # Non-API patterns to skip
    SKIP_PATTERNS = [
        re.compile(r'\.(?:js|css|png|jpg|jpeg|gif|svg|ico|woff|ttf|eot|map)$', re.IGNORECASE),
        re.compile(r'^/(?:static|assets|images|fonts|media|dist|build)/'),
        re.compile(r'^#'),
        re.compile(r'^mailto:'),
        re.compile(r'^javascript:'),
        re.compile(r'localhost'),
        re.compile(r'example\.com'),
        re.compile(r'placeholder'),
    ]

    # Directories to skip
    SKIP_DIRS = {
        "node_modules", "__pycache__", ".git", "dist",
        "build", ".next", ".nuxt", "coverage", ".cache",
    }

    def __init__(self, settings: Settings):
        self.settings = settings
        self.resolver = VariableResolver(settings) if settings.parser.resolve_variables else None
        self.secret_detector = SecretDetector(settings) if settings.parser.detect_secrets else None
        self._parsers: dict[str, tuple] = {}
        self._init_parsers()

        # Merge configured skip dirs
        extra_ignore = set(getattr(settings.parser, "ignore_paths", []))
        self.skip_dirs = self.SKIP_DIRS | extra_ignore

    def _init_parsers(self) -> None:
        """Initialize Tree-sitter parsers for configured languages."""
        try:
            import tree_sitter_javascript as ts_js
            import tree_sitter_python as ts_py
            from tree_sitter import Language, Parser

            if "javascript" in self.settings.parser.languages \
                    or "typescript" in self.settings.parser.languages:
                js_lang = Language(ts_js.language(), "javascript")
                js_parser = Parser()
                js_parser.set_language(js_lang)
                self._parsers["javascript"] = (js_parser, "javascript")
                self._parsers["typescript"] = (js_parser, "javascript")

            if "python" in self.settings.parser.languages:
                py_lang = Language(ts_py.language(), "python")
                py_parser = Parser()
                py_parser.set_language(py_lang)
                self._parsers["python"] = (py_parser, "python")

        except ImportError as e:
            console.print(f"[yellow]Warning: Could not initialize Tree-sitter: {e}[/yellow]")

    def _detect_language(self, file_path: Path) -> Optional[str]:
        ext_map = {
            ".js": "javascript", ".jsx": "javascript",
            ".mjs": "javascript", ".cjs": "javascript",
            ".ts": "typescript", ".tsx": "typescript",
            ".py": "python", ".pyw": "python",
        }
        return ext_map.get(file_path.suffix.lower())

    def _should_skip_dir(self, path: Path) -> bool:
        """Check if any part of the path is in skip list."""
        return any(part in self.skip_dirs for part in path.parts)

    def parse_file(self, file_path: Path) -> ScanResult:
        """Parse a single file and extract endpoints."""
        start_time = time.time()
        result = ScanResult(source_file=file_path)

        language = self._detect_language(file_path)
        if not language or language not in self._parsers:
            return result

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            result.errors.append(f"Read error: {str(e)}")
            return result

        parser, lang_name = self._parsers[language]

        try:
            tree = parser.parse(bytes(content, "utf-8"))

            # Extract endpoints
            seen_urls: set[str] = set()
            for ep in self._extract_endpoints(tree, content, file_path, lang_name):
                sig = f"{ep.method}:{ep.url}"
                if sig not in seen_urls:
                    seen_urls.add(sig)
                    result.endpoints.append(ep)

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

        def walk(node):
            yield node
            for child in node.children:
                yield from walk(child)

        http_functions = set(f.lower() for f in self.HTTP_CLIENT_FUNCTIONS.get(language, []))

        for node in walk(tree.root_node):
            if node.type == "call_expression":
                endpoint = self._analyze_call(node, content, file_path, http_functions)
                if endpoint:
                    yield endpoint

            elif node.type in ("string", "template_string", "string_literal"):
                endpoint = self._analyze_string_node(node, content, file_path)
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
        func_name = None
        method = HTTPMethod.GET

        for child in node.children:
            if child.type == "identifier":
                func_name = content[child.start_byte:child.end_byte].lower()
                break

            elif child.type == "member_expression":
                parts = []
                for subchild in child.children:
                    if subchild.type in ("identifier", "property_identifier"):
                        parts.append(content[subchild.start_byte:subchild.end_byte])

                if parts:
                    obj_name  = ".".join(parts[:-1]).lower()
                    func_name = parts[-1].lower()

                    # Check if object is an HTTP client
                    is_http_obj = any(
                        obj_name == o or obj_name.endswith("." + o)
                        for o in self.HTTP_CLIENT_OBJECTS
                    )

                    if not is_http_obj and func_name not in http_functions:
                        return None

                    method_map = {
                        "get": HTTPMethod.GET,
                        "post": HTTPMethod.POST,
                        "put": HTTPMethod.PUT,
                        "delete": HTTPMethod.DELETE,
                        "patch": HTTPMethod.PATCH,
                    }
                    if func_name in method_map:
                        method = method_map[func_name]
                break

        if not func_name or func_name not in http_functions:
            return None

        # Find URL argument
        for child in node.children:
            if child.type == "arguments":
                for arg in child.children:
                    url = self._extract_url_from_node(arg, content)
                    if url and self._is_api_url(url):
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
                break

        return None

    def _extract_url_from_node(self, node, content: str) -> Optional[str]:
        """Extract URL string from various node types."""
        if node.type in ("string", "template_string", "string_literal"):
            return content[node.start_byte:node.end_byte].strip("'\"`")

        elif node.type == "identifier" and self.resolver:
            var_name = content[node.start_byte:node.end_byte]
            # Skip env variable references
            if var_name in ("process", "env", "undefined", "null"):
                return None
            return self.resolver.resolve(var_name, content, node)

        elif node.type == "binary_expression" and self.resolver:
            return self.resolver.resolve_expression(node, content)

        elif node.type == "template_literal" and self.resolver:
            return self.resolver.resolve_expression(node, content)

        elif node.type == "member_expression":
            # Skip process.env.* references
            text = content[node.start_byte:node.end_byte]
            if "process.env" in text or "os.environ" in text:
                return None

        return None

    def _analyze_string_node(
        self,
        node,
        content: str,
        file_path: Path,
    ) -> Optional[Endpoint]:
        """Analyze a string literal that looks like an API path."""
        value = content[node.start_byte:node.end_byte].strip("'\"`")
        if self._is_api_url(value):
            return Endpoint(
                url=value,
                method=HTTPMethod.GET,
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
        if not url or len(url) < 4:
            return False

        # Skip patterns
        for pattern in self.SKIP_PATTERNS:
            if pattern.search(url):
                return False

        return bool(self.URL_PATTERN.match(url) or self.API_PATH_PATTERN.match(url))

    def parse_directory(self, directory: Path) -> list[ScanResult]:
        """Parse all source files in a directory."""
        results = []

        if not directory.exists():
            return results

        extensions = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py"}
        source_files = []

        for ext in extensions:
            for f in directory.rglob(f"*{ext}"):
                if not self._should_skip_dir(f):
                    source_files.append(f)

        console.print(f"  [dim]Found {len(source_files)} source files to parse[/dim]")

        for file_path in source_files:
            result = self.parse_file(file_path)
            if result.endpoints or result.secrets or result.errors:
                results.append(result)

        return results
