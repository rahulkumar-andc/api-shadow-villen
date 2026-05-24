# 🕵️ Shadow-API Mapper

**Automated Shadow and Zombie API Discovery Tool**

Shadow-API Mapper discovers hidden, undocumented, and deprecated API endpoints in your codebase using hybrid static + dynamic analysis.

[![CI](https://github.com/rahulkumar-andc/api-shadow-villen/actions/workflows/ci.yml/badge.svg)](https://github.com/rahulkumar-andc/api-shadow-villen/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)

---

## 🔍 What It Detects

| Type | Description |
|------|-------------|
| **Shadow API** | Endpoint in code but NOT in your OpenAPI spec |
| **Zombie API** | Deprecated endpoint that is still responding |
| **Ghost API** | Documented in spec but not responding |
| **Secret** | Hardcoded API keys, tokens, passwords in source |

---

## ⚡ Quick Start

```bash
# Install
git clone https://github.com/rahulkumar-andc/api-shadow-villen.git
cd api-shadow-villen
pip install poetry
poetry install

# Scan your local JS/TS/Python codebase
poetry run shadow-mapper parse ./your-project --output results.json

# View results
cat results.json
```

---

## 📦 Installation

**Requirements:** Python 3.11+, Poetry

```bash
pip install poetry
poetry install
poetry run playwright install chromium  # For browser-based harvesting
```

---

## 🛠 Commands

### `parse` — Scan Local Source Files (No Network)
```bash
poetry run shadow-mapper parse ./src \
  --output ./results.json \
  --secrets \
  --resolve
```

### `scan` — Full Pipeline (Harvest + Parse + Probe + Audit)
```bash
poetry run shadow-mapper scan https://your-target.com \
  --output ./scan-output \
  --sarif results.sarif \
  --spec openapi.yaml
```

### `audit` — Compare Against OpenAPI Spec
```bash
poetry run shadow-mapper audit ./results.json \
  --spec openapi.yaml \
  --output audit-report.json \
  --sarif results.sarif
```

### `dashboard` — Interactive Web UI
```bash
poetry run shadow-mapper dashboard ./scan-output/report.json --port 8000
```

### `probe` — Verify Endpoints Are Live
```bash
poetry run shadow-mapper probe ./results.json \
  --output probe-results.json
```

### `bulk` — Scan Multiple Domains
```bash
# domains.txt — one domain per line
poetry run shadow-mapper bulk domains.txt \
  --output ./bulk-results \
  --concurrency 3
```

---

## 🧪 Test It Right Now

```bash
# 1. Create test JS file
mkdir test-app
cat > test-app/api.js << 'EOF'
const API_KEY = "sk_live_realkey1234567890abcdef";

fetch("/api/v1/users");
axios.post("/api/v2/orders");
fetch("/api/admin/secret");      // Shadow API candidate
fetch("/api/v0/deprecated");     // Zombie API candidate
EOF

# 2. Run scan
poetry run shadow-mapper parse ./test-app --output results.json

# 3. See results
python3 -c "
import json
d = json.load(open('results.json'))
print(f'Endpoints: {len(d[\"endpoints\"])}')
print(f'Secrets:   {len(d[\"secrets\"])}')
for e in d['endpoints']:
    print(f'  {e[\"method\"]} {e[\"url\"]}')
"
```

---

## ⚙️ Configuration

Copy and edit the example config:
```bash
cp shadow-mapper.example.yaml shadow-mapper.yaml
```

Key settings:
```yaml
scope:
  allowed_domains:
    - "*.your-domain.com"
  blocked_domains:
    - "localhost"

rate_limit:
  requests_per_second: 10

parser:
  detect_secrets: true
  resolve_variables: true
  ignore_paths:
    - node_modules
    - dist
    - "*.test.js"
```

---

## 🔗 CI/CD Integration

### GitHub Actions
```yaml
- name: Shadow API Scan
  run: |
    poetry run shadow-mapper parse ./src \
      --output current.json

    python scripts/check_new_shadows.py \
      --baseline baseline.json \
      --current current.json
```

### Pre-commit Hook
```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: shadow-mapper-secrets
        name: Detect Hardcoded Secrets
        entry: poetry run shadow-mapper parse
        args: ["./src", "--secrets", "--output", "/dev/null"]
        language: system
        types_or: [javascript, typescript, python]
```

---

## 📊 Output Formats

| Format | Description |
|--------|-------------|
| `JSON` | Machine-readable, full detail |
| `SARIF` | GitHub Security tab integration |
| `HTML` | Visual report, open in browser |
| `CSV`  | Excel-compatible with risk scoring |

---

## 🏗 Project Structure

```
src/shadow_mapper/
├── cli.py              # CLI entry point
├── core/
│   ├── config.py       # Settings management
│   ├── models.py       # Data models
│   ├── safety.py       # Scope enforcement, rate limiting
│   ├── orchestrator.py # Full scan pipeline
│   └── checkpoint.py   # Resumable scans
├── harvester/          # Browser + Wayback Machine
├── parser/             # Tree-sitter AST analysis
├── prober/             # HTTP endpoint verification
├── auditor/            # OpenAPI spec comparison
└── reports/            # HTML, CSV, SARIF output
```

---

## ⚠️ Legal Disclaimer

> This tool is for **authorized security testing only**.
> Only test systems you own or have **explicit written permission** to test.
> Unauthorized use may violate computer crime laws.

---

## 📄 License

MIT — see [LICENSE](LICENSE)

Built by [VILLEN Security](https://github.com/rahulkumar-andc)
