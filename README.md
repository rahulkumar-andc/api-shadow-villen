# 🕵️ Shadow-API Mapper

[![CI/CD Pipeline](https://github.com/villen/shadow-api-mapper/actions/workflows/ci.yml/badge.svg)](https://github.com/villen/shadow-api-mapper/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

**Shadow-API Mapper** is an advanced autonomous security agent designed to discover, map, and audit Shadow APIs and "Zombie" endpoints. It combines static analysis (AST-based secrets/endpoint detection) with dynamic analysis (browser-based harvesting and active probing).

---

## ✨ Key Features

### 🔍 Discovery & Mapping
- **Hybrid Analysis**: Combines source code parsing (JS, TS, Python) with live traffic harvesting.
- **GraphQL Detection**: Automatically detects GraphQL endpoints and introspects schemas.
- **Fail-Closed Security**: Strict URL validation with RFC 1918 (SSRF) and cloud metadata protection.

### 🛡️ Security & Auditing
- **Secret Detection**: Enhanced entropy-based detection for API keys, tokens, and private keys.
- **PII Redaction**: Luhn-validated credit card redaction and UUID-aware filtering.
- **Rate Limit Caching**: Smart caching of 429 responses to avoid hammering targets.

### 📊 Observability & Reporting
- **Live Progress**: Rich CLI dashboards with real-time file/endpoint statistics.
- **Diff Mode**: Compare scans to track new, removed, and changed endpoints over time.
- **HTML Reports**: Modern dark-mode reports with endpoint grids and finding summaries.
- **Structured Logging**: JSON-formatted logs ready for SIEM ingestion.

---

## 🚀 Installation

```bash
# Install with pip
pip install shadow-api-mapper

# Or with poetry
poetry install
poetry run playwright install chromium
```

---

## 📖 Usage

### Full Scan
Run a comprehensive discovery pipeline (Harvest → Parse → Probe → Audit):
```bash
shadow-mapper scan "https://api.example.com" \
  --output ./results \
  --secrets \
  --html-report
```

### Diff Scans
Compare a new scan against a previous baseline:
```bash
shadow-mapper diff \
  --baseline ./results/report-old.json \
  --current ./results/report-new.json
```

### Docker
```bash
docker run --rm -v $(pwd)/results:/app/results \
  ghcr.io/villen/shadow-api-mapper:latest \
  scan "https://api.example.com" --output /app/results
```

---

## 🛠️ Configuration

Configure behaviors via `shadow-mapper.yaml` or environment variables:

```yaml
scope:
  allowed_domains: ["api.example.com", "*.example.com"]
  blocked_domains: ["admin.example.com"]
  allow_ip_addresses: false
  ssrf_protection: true

parser:
  languages: ["javascript", "typescript", "python"]
  detect_secrets: true

rate_limit:
  requests_per_second: 10
  burst: 20
```

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on setting up your development environment.

### Development Setup
```bash
poetry install
poetry run pre-commit install
```

### Running Tests
```bash
poetry run pytest tests/
```

---

## ⚠️ Legal Disclaimer

**Shadow-API Mapper** is designed for defensive security research and authorized bug bounty hunting only.
- 🔴 **Do not** scan targets without explicit permission.
- 🔴 **Do not** use for illegal surveillance or harm.
- 🔴 **Do not** share discovered vulnerabilities publicly without responsible disclosure.

The authors are not responsible for misuse of this tool. Use responsibly.
