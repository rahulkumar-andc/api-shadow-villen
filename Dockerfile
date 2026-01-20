# Shadow-API Mapper Dockerfile
# Multi-stage build for optimal image size

# ============================================
# Stage 1: Builder
# ============================================
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
ENV POETRY_HOME="/opt/poetry"
ENV POETRY_VIRTUALENVS_CREATE=false
ENV PATH="$POETRY_HOME/bin:$PATH"
RUN curl -sSL https://install.python-poetry.org | python3 -

# Copy dependency files
COPY pyproject.toml poetry.lock* ./

# Install dependencies
RUN poetry install --no-interaction --no-ansi --only main

# Copy source code
COPY src/ ./src/

# Install the package
RUN poetry install --no-interaction --no-ansi --only main

# ============================================
# Stage 2: Runtime
# ============================================
FROM python:3.11-slim as runtime

WORKDIR /app

# Create non-root user for security
RUN groupadd -r shadowmapper && useradd -r -g shadowmapper shadowmapper

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # For Playwright/Chromium
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libdbus-1-3 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpango-1.0-0 \
    libcairo2 \
    # For general use
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy source code
COPY --from=builder /app/src /app/src

# Install Playwright browsers as root, then fix permissions
RUN pip install playwright && playwright install chromium && playwright install-deps chromium
RUN chown -R shadowmapper:shadowmapper /root/.cache 2>/dev/null || true

# Create directories for output
RUN mkdir -p /app/output /app/cache && chown -R shadowmapper:shadowmapper /app

# Switch to non-root user
USER shadowmapper

# Add shadow-mapper to PATH
ENV PYTHONPATH="/app/src:$PYTHONPATH"
ENV PATH="/app/.local/bin:$PATH"

# Default command
ENTRYPOINT ["python", "-m", "shadow_mapper.cli"]
CMD ["--help"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "from shadow_mapper import __version__; print(__version__)" || exit 1

# Labels
LABEL org.opencontainers.image.title="Shadow-API Mapper"
LABEL org.opencontainers.image.description="Automated Shadow and Zombie API Discovery Tool"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.authors="VILLEN Security"
LABEL org.opencontainers.image.source="https://github.com/villen/shadow-api-mapper"
LABEL org.opencontainers.image.licenses="MIT"
