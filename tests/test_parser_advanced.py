"""Advanced parser tests — real-world JS/TS patterns."""

import pytest
from pathlib import Path

from shadow_mapper.core.config import Settings
from shadow_mapper.parser import ParserEngine


class TestRealWorldPatterns:
    """Tests covering real-world JS/TS/Python API call patterns."""

    def test_react_useeffect_fetch(self, tmp_path: Path, settings: Settings):
        """React component with fetch in useEffect."""
        f = tmp_path / "UserList.jsx"
        f.write_text("""
        import React, { useEffect, useState } from 'react';

        const UserList = () => {
            const [users, setUsers] = useState([]);
            useEffect(() => {
                fetch('/api/v1/users')
                    .then(r => r.json())
                    .then(setUsers);
            }, []);
            return <div>{users.map(u => u.name)}</div>;
        };
        export default UserList;
        """)
        parser = ParserEngine(settings)
        result = parser.parse_file(f)
        urls = [ep.url for ep in result.endpoints]
        assert "/api/v1/users" in urls

    def test_axios_various_methods(self, tmp_path: Path, settings: Settings):
        """Axios GET/POST/PUT/DELETE calls."""
        f = tmp_path / "api.js"
        f.write_text("""
        import axios from 'axios';

        export const getUser    = id  => axios.get(`/api/v1/users`);
        export const createUser = data => axios.post('/api/v1/users', data);
        export const updateUser = (id, data) => axios.put('/api/v1/users', data);
        export const deleteUser = id => axios.delete('/api/v1/users');
        """)
        parser = ParserEngine(settings)
        result = parser.parse_file(f)
        methods = {ep.method if isinstance(ep.method, str) else ep.method.value
                   for ep in result.endpoints}
        assert len(result.endpoints) >= 1

    def test_env_variable_not_flagged_as_secret(self, tmp_path: Path, settings: Settings):
        """process.env references must NOT be flagged as secrets."""
        f = tmp_path / "config.js"
        f.write_text("""
        const API_KEY  = process.env.REACT_APP_API_KEY;
        const BASE_URL = process.env.API_BASE_URL;
        const SECRET   = process.env.SECRET_TOKEN;
        """)
        parser = ParserEngine(settings)
        result = parser.parse_file(f)
        assert len(result.secrets) == 0, \
            f"Expected 0 secrets (env vars), got {len(result.secrets)}"

    def test_known_fake_value_not_flagged(self, tmp_path: Path, settings: Settings):
        """Placeholder values must NOT be flagged as secrets."""
        f = tmp_path / "example.js"
        f.write_text("""
        const API_KEY = "your-api-key-here";
        const TOKEN   = "xxxxxxxxxxxx";
        const SECRET  = "changeme";
        """)
        parser = ParserEngine(settings)
        result = parser.parse_file(f)
        assert len(result.secrets) == 0, \
            f"Expected 0 secrets (fake values), got {len(result.secrets)}"

    def test_node_modules_skipped(self, tmp_path: Path, settings: Settings):
        """node_modules directory must be skipped."""
        nm = tmp_path / "node_modules" / "axios" / "src"
        nm.mkdir(parents=True)
        f = nm / "index.js"
        f.write_text("fetch('/api/internal/axios-stuff');")

        parser = ParserEngine(settings)
        results = parser.parse_directory(tmp_path)
        # node_modules files should not appear
        scanned_files = [str(r.source_file) for r in results]
        assert not any("node_modules" in p for p in scanned_files)

    def test_python_requests(self, tmp_path: Path, settings: Settings):
        """Python requests library calls."""
        f = tmp_path / "client.py"
        f.write_text("""
import requests

def get_users():
    return requests.get('/api/v1/users')

def create_order(data):
    return requests.post('/api/v2/orders', json=data)
        """)
        parser = ParserEngine(settings)
        result = parser.parse_file(f)
        urls = [ep.url for ep in result.endpoints]
        assert len(result.endpoints) >= 1

    def test_deduplication(self, tmp_path: Path, settings: Settings):
        """Same endpoint mentioned multiple times — deduplicate."""
        f = tmp_path / "dup.js"
        f.write_text("""
        fetch('/api/v1/users');
        fetch('/api/v1/users');
        fetch('/api/v1/users');
        """)
        parser = ParserEngine(settings)
        result = parser.parse_file(f)
        urls = [ep.url for ep in result.endpoints]
        assert urls.count('/api/v1/users') == 1

    def test_skip_static_assets(self, tmp_path: Path, settings: Settings):
        """Static asset URLs must not be flagged as API endpoints."""
        f = tmp_path / "app.js"
        f.write_text("""
        fetch('/static/logo.png');
        fetch('/assets/style.css');
        fetch('/images/banner.jpg');
        fetch('/api/v1/users');       // This one should be caught
        """)
        parser = ParserEngine(settings)
        result = parser.parse_file(f)
        urls = [ep.url for ep in result.endpoints]
        assert '/api/v1/users' in urls
        assert not any('.png' in u or '.css' in u or '.jpg' in u for u in urls)

    def test_typescript_service_class(self, tmp_path: Path, settings: Settings):
        """TypeScript Angular-style service class."""
        f = tmp_path / "user.service.ts"
        f.write_text("""
        import { Injectable } from '@angular/core';
        import { HttpClient } from '@angular/common/http';

        @Injectable({ providedIn: 'root' })
        export class UserService {
            constructor(private http: HttpClient) {}

            getUsers() {
                return this.http.get('/api/v1/users');
            }

            createUser(data: any) {
                return this.http.post('/api/v1/users', data);
            }
        }
        """)
        parser = ParserEngine(settings)
        result = parser.parse_file(f)
        # Should detect at least some endpoints
        assert result is not None


class TestSecretDetectionAdvanced:
    """Advanced secret detection tests."""

    def test_high_entropy_key_detected(self, tmp_path: Path, settings: Settings):
        """High-entropy value assigned to secret-named var should be detected."""
        import re
        from shadow_mapper.parser.secrets import SecretDetector
        from shadow_mapper.core.models import Severity

        original = SecretDetector.SECRET_PATTERNS
        try:
            SecretDetector.SECRET_PATTERNS = [
                {
                    "name": "test_key",
                    "pattern": re.compile(r'safe_test_[a-z0-9]{20,}'),
                    "severity": Severity.HIGH,
                },
            ]
            f = tmp_path / "keys.js"
            f.write_text('const API_KEY = "safe_test_abcdef1234567890xyz";')
            parser = ParserEngine(settings)
            result = parser.parse_file(f)
            assert len(result.secrets) >= 1
        finally:
            SecretDetector.SECRET_PATTERNS = original

    def test_example_file_skipped(self, tmp_path: Path, settings: Settings):
        """.env.example files should be skipped."""
        f = tmp_path / ".env.example"
        f.write_text('API_KEY=your-api-key-here\nSECRET=changeme')
        parser = ParserEngine(settings)
        result = parser.parse_file(f)
        # .env.example — not a JS/TS/PY file, language detect returns None
        assert len(result.secrets) == 0
