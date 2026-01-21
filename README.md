# 🕵️ Shadow-API Mapper

[![CI/CD Pipeline](https://github.com/rahulkumar-andc/api-shadow-villen/actions/workflows/ci.yml/badge.svg)](https://github.com/rahulkumar-andc/api-shadow-villen/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

**Shadow-API Mapper** is an advanced autonomous security agent designed to discover, map, and audit Shadow APIs and "Zombie" endpoints. It combines static analysis (AST-based secrets/endpoint detection) with dynamic analysis (browser-based harvesting and active probing).

---

## ✨ Key Features

### 🔍 Discovery & Mapping
- **Hybrid Analysis**: Combines source code parsing (JS, TS, Python) with live traffic harvesting.
- **Bulk Scanning**: Concurrent scanning of 300+ subdomains with unified reporting (`shadow-mapper bulk`).
- **GraphQL Detection**: Automatically detects GraphQL endpoints and introspects schemas.

### 🛡️ Security & Auditing
- **Shadow Fuzzing**: Probes for hidden parameters (`?admin=true`) and mass assignment vulnerabilities.
- **Secret Detection**: Enhanced entropy-based detection for API keys, tokens, and private keys.
- **Fail-Closed Security**: Strict URL validation with RFC 1918 (SSRF) and cloud metadata protection.

### 📊 Observability & Reporting
- **Web Dashboard**: Interactive visual dashboard to explore endpoints and secrets.
- **DevEx**: Pre-commit hooks to stop secrets from entering your codebase.
- **Diff Mode**: Compare scans to track new, removed, and changed endpoints over time.
- **HTML Reports**: Modern dark-mode reports with endpoint grids and finding summaries.

---

## 🚀 Installation

```bash
# Install with pip
pip install shadow-api-mapper

# Or with poetry (Recommended)
poetry install
poetry run playwright install chromium
```

---

## 📖 Usage

### 1. Full Scan (Single Target)
Run a comprehensive discovery pipeline (Harvest → Parse → Probe → Audit):
```bash
shadow-mapper scan "https://api.example.com" \
  --output ./results \
  --fuzz \
  --html-report
```

### 2. Bulk Scan (Multiple Targets) 📦
Scan a list of domains (e.g., from `subfinder` or `amass`):
```bash
shadow-mapper bulk ./domains.txt \
  --output ./bulk-results \
  --concurrency 5
```

### 3. Interactive Dashboard 📊
Visualize your results in a local web interface:
```bash
shadow-mapper dashboard ./results/report.json
```

### 4. Diff Scans
Compare a new scan against a previous baseline:
```bash
shadow-mapper diff \
  --baseline ./results/report-old.json \
  --current ./results/report-new.json
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
```

---

## 🛡️ Pre-commit Hook

 Prevent secrets from being committed by adding this to your `.pre-commit-config.yaml`:

```yaml
  - repo: local
    hooks:
      - id: shadow-mapper-secrets
        name: Shadow API Secret Check 🕵️
        entry: poetry run shadow-mapper parse
        language: system
        types: [file]
```

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on setting up your development environment.

---

## ⚠️ Legal Disclaimer

**Shadow-API Mapper** is designed for defensive security research and authorized bug bounty hunting only.
- 🔴 **Do not** scan targets without explicit permission.
- 🔴 **Do not** use for illegal surveillance or harm.
- 🔴 **Do not** share discovered vulnerabilities publicly without responsible disclosure.

The authors are not responsible for misuse of this tool. Use responsibly.
