# Shadow-API Mapper

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

> **Automated Shadow and Zombie API Discovery Tool**

A comprehensive security tool that combines **AST-based static analysis** (Tree-sitter) with **high-performance dynamic probing** (httpx/Playwright) to discover undocumented and deprecated API endpoints.

## ⚠️ Legal Disclaimer

**This tool is designed exclusively for authorized security testing.** 

- Only use on systems you own or have explicit written permission to test
- Unauthorized scanning may violate computer crime laws
- The authors assume no liability for misuse of this software
- Always follow responsible disclosure practices

## Features

### 🕷️ Harvester Module
- **Playwright-based Crawling**: Headless browser for SPA JavaScript extraction
- **Source Map Detection**: Automatic `.map` file discovery and parsing
- **Historical Mining**: Wayback Machine integration for finding deprecated endpoints
- **Subdomain Enumeration**: Passive reconnaissance via crt.sh

### 🧠 Parser Module
- **AST Analysis**: Tree-sitter parsing for context-aware endpoint detection
- **Variable Resolution**: String concatenation and constant propagation
- **Multi-Language**: JavaScript, TypeScript, Python support
- **Secret Detection**: API keys and tokens identification

### 🎯 Prober Module
- **Async Scanning**: High-concurrency httpx with HTTP/2
- **Smart Rate Limiting**: Adaptive throttling to avoid WAF detection
- **Zombie Detection**: Deprecation headers and version permutation
- **Nuclei Integration**: Template-based vulnerability scanning

### 📊 Auditor Module
- **Spec Comparison**: OpenAPI/Swagger diff analysis
- **SARIF Reporting**: CI/CD integration ready
- **Auto-Generation**: Skeleton spec creation for discovered endpoints

## Installation

```bash
# Clone repository
git clone https://github.com/villen/shadow-api-mapper.git
cd shadow-api-mapper

# Install with Poetry
poetry install

# Install Playwright browsers
poetry run playwright install chromium
```

## Quick Start

```bash
# Full scan pipeline
shadow-mapper scan https://target.example.com --output report.sarif

# Individual steps
shadow-mapper harvest https://target.example.com --output ./cache
shadow-mapper parse ./cache --output endpoints.json
shadow-mapper probe endpoints.json --dry-run
shadow-mapper audit endpoints.json --spec openapi.yaml
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `harvest` | Collect JavaScript and assets from target |
| `parse` | Extract endpoints via AST analysis |
| `probe` | Verify endpoints against live infrastructure |
| `audit` | Compare findings against OpenAPI spec |
| `scan` | Execute full discovery pipeline |

## Configuration

Create a `shadow-mapper.yaml` configuration file:

```yaml
scope:
  allowed_domains:
    - "*.example.com"
    - "api.example.com"
  
rate_limit:
  requests_per_second: 10
  burst: 20
  
prober:
  timeout: 30
  follow_redirects: true
  verify_ssl: true
  
output:
  format: sarif  # sarif, json, csv
  redact_pii: true
```

## CI/CD Integration

### GitHub Actions

```yaml
name: API Governance Scan
on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Shadow-API Mapper
        run: |
          pip install shadow-api-mapper
          shadow-mapper scan ${{ secrets.TARGET_URL }} --sarif results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Harvester  │────▶│   Parser    │────▶│   Prober    │────▶│   Auditor   │
│             │     │             │     │             │     │             │
│ • Playwright│     │ • Tree-sitter│    │ • httpx     │     │ • Spec Diff │
│ • Wayback   │     │ • Resolver  │     │ • Nuclei    │     │ • SARIF     │
│ • crt.sh    │     │ • Secrets   │     │ • Heuristics│     │ • Generator │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
```

## Output Example

```json
{
  "shadow_apis": [
    {
      "endpoint": "/api/v1/admin/users",
      "method": "GET",
      "source": "app.bundle.js:1245",
      "status": "ACTIVE_UNPROTECTED",
      "severity": "HIGH"
    }
  ],
  "zombie_apis": [
    {
      "endpoint": "/api/v0/legacy/auth",
      "method": "POST",
      "deprecation_date": "2024-01-15",
      "severity": "MEDIUM"
    }
  ]
}
```

## Development

```bash
# Run tests
poetry run pytest

# Type checking
poetry run mypy src/

# Linting
poetry run ruff check src/
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Run tests and linting
4. Commit changes (`git commit -m 'Add amazing feature'`)
5. Push to branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [Tree-sitter](https://tree-sitter.github.io/) - Incremental parsing library
- [httpx](https://www.python-httpx.org/) - Async HTTP client
- [Playwright](https://playwright.dev/) - Browser automation
- [Nuclei](https://nuclei.projectdiscovery.io/) - Vulnerability scanner
