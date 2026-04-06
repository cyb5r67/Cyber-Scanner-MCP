FROM python:3.10-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies (nmap for Module 4)
RUN apt-get update && \
    apt-get install -y --no-install-recommends nmap libpq-dev && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir -e ".[ob1]" 2>/dev/null || pip install --no-cache-dir \
    "fastmcp>=2.0" \
    "python-nmap>=0.7.1" \
    "anthropic>=0.50.0" \
    "psycopg2-binary>=2.9"

# Copy application code
COPY scanner/ scanner/
COPY agent/ agent/
COPY find_lib.ps1 find_lib.sh ./

# Create runtime directories
RUN mkdir -p data/baselines data/sboms data/oscal logs

# Create non-root user
RUN groupadd -r scanner && useradd -r -g scanner -d /app scanner && \
    chown -R scanner:scanner /app
USER scanner

# Health check via CLI
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD python -m scanner.cli list-drives --json || exit 1

# Default: run MCP server
CMD ["python", "-m", "scanner.server"]
