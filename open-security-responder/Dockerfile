# Open Security Responder - SOAR Orchestration Service

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
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
        git \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
# --require-hashes: refuse to install an artefact whose hash does not match the
# lockfile (WILDBO-DEP-04).
# pip is the one in the digest-pinned base image (24.0): no `--upgrade pip`,
# which installed whatever PyPI served that day, unhashed, and then ran it
# (#657). --no-build-isolation: a source distribution in the lockfile is built
# with the base image's setuptools instead of one downloaded for the build,
# so nothing is fetched that the lockfile does not name with a hash.
RUN pip install --no-cache-dir --require-hashes --no-build-isolation -r requirements.txt

# Install the shared package, provided via the `shared` additional build
# context (see docker-compose.yml / CI), with the extras of the modules this
# service imports (scripts/check_shared_dependencies.py keeps the two equal).
# No --no-deps: pip resolves what those extras require, and with --no-index
# it can only resolve it against what the hash-checked install above put in
# the image, so the build fails when requirements.txt does not provide a
# package or pins it below the floor the shared package declares. `pip check`
# then fails the build for any other requirement the environment does not
# meet. With --no-deps nothing looked: seven images of eight lacked a
# declared dependency of the package (#722).
# --no-index --no-build-isolation: build it with the setuptools already in
# the image (the digest-pinned base image's, or the one a lockfile pins by
# hash). Without them pip made an isolated build environment and downloaded
# the latest setuptools from PyPI, unhashed, at every build (#657).
COPY --from=shared . /tmp/open-security-shared
RUN pip install --no-cache-dir --no-index --no-build-isolation \
        "/tmp/open-security-shared[fastapi,metrics]" \
    && pip check

# Copy project
COPY . .

# Create directories
RUN mkdir -p /app/playbooks /app/logs

# Create non-root user
RUN adduser --disabled-password --gecos '' responder \
    && chown -R responder:responder /app

# Make entrypoint script executable
RUN chmod +x /app/scripts/entrypoint.sh

USER responder

# Expose port
EXPOSE 8018

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8018/health || exit 1

# Use entrypoint script to start both Dramatiq worker and uvicorn
CMD ["/app/scripts/entrypoint.sh"]
