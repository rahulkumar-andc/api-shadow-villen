# Contributing to Shadow-API Mapper

Thank you for your interest in contributing! We welcome PRs for bugs, features, and documentation.

## 🛠️ Development Environment

We use **Poetry** for dependency management and **Ruff** for linting.

### 1. Setup
```bash
git clone https://github.com/villen/shadow-api-mapper.git
cd shadow-api-mapper
poetry install
poetry run playwright install chromium
```

### 2. Code Quality
Ensure your code passes all checks before submitting:

```bash
# Run tests
poetry run pytest tests/

# Run linter
poetry run ruff check src/

# Run type checker
poetry run mypy src/
```

### 3. Commit Guidelines
- Use descriptive commit messages.
- Reference issue numbers if applicable.
- Keep PRs focused on a single change.

## 🏗️ Project Structure
- `src/shadow_mapper/core`: Core logic (config, safety, models)
- `src/shadow_mapper/parser`: AST parsing and secret detection
- `src/shadow_mapper/harvester`: Browser automation
- `src/shadow_mapper/prober`: HTTP probing
- `tests/`: Pytest suite

## 🛡️ Security Guidelines
- Do not commit secrets/keys (even fake ones) unless in `tests/`.
- Ensure new features have appropriate safety guards (e.g., rate limits, scope checks).
- If you find a security vulnerability in the tool itself, please report it via [SECURITY.md](SECURITY.md).
