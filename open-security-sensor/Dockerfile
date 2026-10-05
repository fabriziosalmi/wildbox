# Open Security Sensor Dockerfile
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

# Install system dependencies
# --no-install-recommends: only what is named here, not what these packages
# recommend (#726).
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Install osquery - detect architecture and install accordingly.
# The package is checked against the SHA-256 recorded here before dpkg runs
# it: the URL names a version, and nothing else said that the bytes behind it
# were the ones this image was built with last time (#657). The hashes are
# those of the 5.10.2 release; pkg.osquery.io and the GitHub release
# (github.com/osquery/osquery/releases/tag/5.10.2) serve the same files.
# Change them together with the version.
#
# Plain `dpkg -i`, no `|| apt-get install -f -y` behind it: the package
# depends on libc6 and zlib1g, which the base image has, and the fallback
# could not have repaired anything, because the layer above has already
# removed the package lists it would need (#726).
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then \
        OSQUERY_SHA256=5a7e6a8bb5dd666a22afff092bd8b9e25a92a37f62e9f3cb6991ea3ea93efb08; \
    elif [ "$ARCH" = "arm64" ]; then \
        OSQUERY_SHA256=837470e7e24807f57359a79fad38c9c4e1cdfad9525fa090c999821cc77bce48; \
    else \
        echo "Unsupported architecture: $ARCH" && exit 1; \
    fi && \
    curl -fsSL "https://pkg.osquery.io/deb/osquery_5.10.2-1.linux_${ARCH}.deb" -o osquery.deb && \
    echo "${OSQUERY_SHA256}  osquery.deb" | sha256sum -c - && \
    dpkg -i osquery.deb && \
    rm osquery.deb && \
    # Create symlinks to make osqueryd available in PATH
    if [ -f /opt/osquery/bin/osqueryd ]; then \
        ln -sf /opt/osquery/bin/osqueryd /usr/local/bin/osqueryd; \
        ln -sf /opt/osquery/bin/osqueryi /usr/local/bin/osqueryi; \
    elif [ -f /usr/bin/osqueryd ]; then \
        ln -sf /usr/bin/osqueryd /usr/local/bin/osqueryd; \
        ln -sf /usr/bin/osqueryi /usr/local/bin/osqueryi; \
    else \
        echo "osqueryd not found in expected locations" && exit 1; \
    fi

# Copy requirements and install Python dependencies
COPY requirements.txt .
# --require-hashes: refuse to install an artefact whose hash does not match the
# lockfile. Version pinning alone stops a NEW release entering the build; it
# does not stop the same version's bytes from changing (WILDBO-DEP-04).
# pip is the one in the digest-pinned base image (24.0): no `--upgrade pip`,
# which installed whatever PyPI served that day, unhashed, and then ran it
# (#657). --no-build-isolation: a source distribution in the lockfile is built
# with the base image's setuptools instead of one downloaded for the build,
# so nothing is fetched that the lockfile does not name with a hash.
RUN pip install --no-cache-dir --require-hashes --no-build-isolation -r requirements.txt

# Install the shared package, provided via the `shared` additional build
# context (see docker-compose.yml / CI), with no extra: the sensor is
# aiohttp and imports no module of the package that needs one
# (scripts/check_shared_dependencies.py fails when that stops being true).
# No --no-deps: pip resolves what the package requires, and with --no-index
# it can only resolve it against what the hash-checked install above put in
# the image. `pip check` then fails the build for any requirement the
# environment does not meet. With --no-deps nothing looked, and the package
# declared FastAPI, passlib and PyJWT as dependencies of this image too
# (#722).
# --no-index --no-build-isolation: build it with the setuptools already in
# the image (the digest-pinned base image's, or the one a lockfile pins by
# hash). Without them pip made an isolated build environment and downloaded
# the latest setuptools from PyPI, unhashed, at every build (#657).
COPY --from=shared . /tmp/open-security-shared
RUN pip install --no-cache-dir --no-index --no-build-isolation /tmp/open-security-shared \
    && pip check

# Copy application code
COPY . .

# Install the sensor package. --no-index --no-deps --no-build-isolation: as
# for the shared package above. A plain `pip install -e .` resolved setup.py's
# install_requires against PyPI, outside the lockfile, for anything the
# hash-checked install had not already satisfied. `pip check` says whether it
# had: it fails the build when the lock does not meet install_requires.
RUN pip install --no-cache-dir --no-index --no-deps --no-build-isolation -e . \
    && pip check

# Create directories
RUN mkdir -p /etc/security-sensor /var/log/security-sensor /var/lib/security-sensor

# Copy configuration template
COPY config.yaml.example /etc/security-sensor/config.yaml.example

# Create non-root user
RUN useradd -r -s /bin/false -m -d /var/lib/security-sensor sensor

# Set proper permissions
RUN chown -R sensor:sensor /var/lib/security-sensor /var/log/security-sensor
RUN chmod 755 /etc/security-sensor

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8004/health || exit 1

# Expose API port
EXPOSE 8004

# Switch to non-root user
USER sensor

# Set environment variables
ENV PYTHONPATH=/app
ENV SENSOR_LOGGING_LEVEL=INFO
ENV PATH="/usr/local/bin:/usr/bin:/bin:$PATH"

# Run the sensor
CMD ["python", "main.py", "--config", "/etc/security-sensor/config.yaml"]
