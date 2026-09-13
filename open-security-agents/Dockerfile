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
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
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
COPY . .

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser

# Create logs directory
RUN mkdir -p logs && chown -R appuser:appuser /app

# Make entrypoint script executable
RUN chmod +x /app/scripts/entrypoint.sh

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8006

# Use entrypoint script to start both Celery worker and uvicorn
CMD ["/app/scripts/entrypoint.sh"]
