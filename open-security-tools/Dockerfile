# Python 3.11, matching the other seven Python services and the CI test
# matrix. This image used to be 3.12 while its siblings were 3.11, so the
# shared package had to work on both and the service's unit tests ran in CI
# on an interpreter it did not ship (WILDBO-BLD-04).
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
# the slim image).
#
# The asset is the one for the platform the image is built for. This used to
# download Linux-64bit whatever the platform, so an image built on or for
# arm64 (an Apple Silicon laptop, a Graviton or Ampere host) shipped an
# x86-64 binary: the tool answered "exec format error" at the first scan, or
# ran under emulation where the host happened to have it (#726). TARGETARCH
# is set by BuildKit; an architecture with no checksum below fails the build.
#
# The tarball is checked against a SHA-256 recorded here before it is
# unpacked: a release asset can be replaced under the same version (#657).
# The values are the Linux-64bit and Linux-ARM64 lines of the release's
# trivy_${TRIVY_VERSION}_checksums.txt; change them together with the
# version.
ARG TRIVY_VERSION=0.72.0
ARG TRIVY_SHA256_AMD64=bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea
ARG TRIVY_SHA256_ARM64=2ca2c023109c2db6b2b77366b6717291452d4531167377d95c79547f0c8e3467
ARG TARGETARCH
RUN case "${TARGETARCH}" in \
        amd64) TRIVY_ASSET=Linux-64bit; TRIVY_SHA256="${TRIVY_SHA256_AMD64}" ;; \
        arm64) TRIVY_ASSET=Linux-ARM64; TRIVY_SHA256="${TRIVY_SHA256_ARM64}" ;; \
        *) echo "Unsupported architecture for Trivy: '${TARGETARCH}' (amd64 and arm64 have a pinned checksum)" >&2; exit 1 ;; \
    esac \
    && curl -sfL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${TRIVY_ASSET}.tar.gz" \
        -o /tmp/trivy.tar.gz \
    && echo "${TRIVY_SHA256}  /tmp/trivy.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
    && rm /tmp/trivy.tar.gz \
    && trivy --version

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash --user-group wildbox

# Copy requirements and install Python dependencies
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
