# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Yes     |
| < 1.0   | ❌ No      |

## Reporting a Vulnerability

If you find a security vulnerability **in this tool itself**, please report it responsibly:

1. **Do NOT** open a public GitHub issue
2. Email: `security@villen.dev`
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (optional)

We will respond within **48 hours** and aim to release a fix within **7 days**.

---

## Responsible Use

This tool is designed for **authorized security testing only**.

### You MUST:
- Own the systems you test, OR have **explicit written authorization**
- Comply with all applicable laws and regulations
- Follow responsible disclosure for any vulnerabilities you discover
- Use rate limiting to avoid disrupting target services

### You MUST NOT:
- Test systems without authorization
- Use this tool for malicious purposes
- Attempt to access, modify, or exfiltrate data from unauthorized systems
- Circumvent scope controls built into the tool

### Legal Notice
Unauthorized use of this tool against systems you do not own or have
permission to test may violate computer crime laws including (but not
limited to) the Computer Fraud and Abuse Act (CFAA) in the US, the
Computer Misuse Act in the UK, and similar laws in other jurisdictions.

The authors of Shadow-API Mapper disclaim all liability for unauthorized use.

---

## Built-in Safety Controls

Shadow-API Mapper includes several safety controls:

| Control | Description |
|---------|-------------|
| **Scope Enforcement** | Domain allowlist/blocklist with fail-closed validation |
| **SSRF Protection** | Blocks internal IPs, cloud metadata endpoints |
| **Rate Limiting** | Token bucket + exponential backoff |
| **URL Validation** | Strict scheme validation, no embedded credentials |
| **Legal Disclaimer** | Displayed before every scan |
| **Dry Run Mode** | Preview without making any requests |

These controls are NOT a substitute for proper authorization.
