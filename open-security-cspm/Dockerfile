# Open Security CSPM - Multi-stage Dockerfile

# Build stage: install build tools and compile dependencies
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc \
        g++ \
        pkg-config \
        libssl-dev \
        libffi-dev \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir --prefix=/install -r requirements.txt

# Runtime stage: minimal image without build tools
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# Install only runtime dependencies (curl for healthcheck)
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Install the shared package, provided via the `shared` additional build
# context (see docker-compose.yml / CI). --no-deps: its deps already come from
# this service's requirements.txt.
COPY --from=shared . /tmp/open-security-shared
RUN pip install --no-deps /tmp/open-security-shared

# Copy project
COPY . .

# Create directories
RUN mkdir -p /app/logs /app/config /app/reports

# Create non-root user
RUN adduser --disabled-password --gecos '' cspm \
    && chown -R cspm:cspm /app

# Switch to non-root user
USER cspm

# Expose port
EXPOSE 8019

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8019/health || exit 1

# Default command
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8019"]
