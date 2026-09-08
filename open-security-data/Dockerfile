# Base image pinned by digest: a floating tag is republished upstream, so the
# same commit built a month apart produced a different interpreter patch level,
# a different OpenSSL and a different set of OS CVEs, with nothing recording
# which one shipped (WILDBO-BLD-01). Dependabot's docker ecosystem proposes
# digest bumps as reviewable PRs.
FROM python:3.11-slim@sha256:9534e5a8e315485d4061ed659af0fd78a284c015f9b73661b41d6bab25604534

# Build metadata. Nothing used to be baked in, so an image identified by digest,
# retagged, or copied to another registry lost the link to its commit -- the tag
# was the only trace (WILDBO-BLD-03). CI passes GIT_SHA=${{ github.sha }}.
ARG GIT_SHA=unknown
ARG BUILD_DATE=unknown
ENV WILDBOX_GIT_SHA=$GIT_SHA \
    WILDBOX_BUILD_DATE=$BUILD_DATE
LABEL org.opencontainers.image.revision=$GIT_SHA \
      org.opencontainers.image.created=$BUILD_DATE \
      org.opencontainers.image.source="https://github.com/fabriziosalmi/wildbox"
# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies
# --require-hashes: refuse to install an artefact whose hash does not match the
# lockfile. Version pinning alone stops a NEW release entering the build; it
# does not stop the same version's bytes from changing (WILDBO-DEP-04).
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

# Install the shared package, provided via the `shared` additional build
# context (see docker-compose.yml / CI). --no-deps: its deps already come from
# this service's requirements.txt.
COPY --from=shared . /tmp/open-security-shared
RUN pip install --no-deps /tmp/open-security-shared

# Copy application code
COPY app/ ./app/
COPY manage.py ./

# Copy config and scripts if they exist
COPY README.md QUICKSTART.md ./

# Create necessary directories
RUN mkdir -p /app/data /app/logs

# Create non-root user
RUN useradd --create-home --shell /bin/bash --uid 1000 appuser && \
    chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 8002

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8002/health || exit 1

# Default command
CMD ["python", "-m", "app.api.main"]
