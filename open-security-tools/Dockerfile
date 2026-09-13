# Python 3.11, matching the other seven Python services and the CI test
# matrix. This image used to be 3.12 while its siblings were 3.11, so the
# shared package had to work on both and the service's unit tests ran in CI
# on an interpreter it did not ship (WILDBO-BLD-04).
# Base image pinned by digest: a floating tag is republished upstream, so the
# same commit built a month apart produced a different interpreter patch level,
# a different OpenSSL and a different set of OS CVEs, with nothing recording
# which one shipped (WILDBO-BLD-01). Dependabot's docker ecosystem proposes
# digest bumps as reviewable PRs.
FROM python:3.14-slim@sha256:cad9a2c871761c413caa6fdd6441c783451e740a48aaeba60ae62a8b53525ef6

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
# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# Install system dependencies
# --no-install-recommends keeps the layer to what is actually needed.
#
# Versions are NOT pinned here (WILDBO-BLD-05). nmap is the engine behind several
# scanners, so its version does change observable behaviour, and pinning it would
# make this layer reproducible -- but a pinned apt version stops receiving
# security updates and breaks the build when Debian drops it from the index.
# The base image is digest-pinned, which fixes the interpreter and the OS
# snapshot; that is where most of the variation was.
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    curl \
    nmap \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Trivy: the scan engine behind the container_security_scanner tool. Pinned so
# the image is reproducible; the vulnerability DB is fetched at first run.
# Download the release tarball directly (the install.sh path was unreliable in
# the slim image). CI/prod build for linux/amd64 -> the Linux-64bit asset.
ARG TRIVY_VERSION=0.72.0
RUN curl -sfL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
    -o /tmp/trivy.tar.gz \
    && tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
    && rm /tmp/trivy.tar.gz \
    && trivy --version

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash --user-group wildbox

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --require-hashes -r requirements.txt

# Install the shared package, provided via the `shared` additional build
# context (see docker-compose.yml / CI). --no-deps: its deps already come from
# this service's requirements.txt.
COPY --from=shared . /tmp/open-security-shared
RUN pip install --no-deps /tmp/open-security-shared

# Copy application code
COPY . .

# Create necessary directories and set permissions
RUN mkdir -p /app/logs && \
    chown -R wildbox:wildbox /app

# Switch to non-root user
USER wildbox

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default command
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
