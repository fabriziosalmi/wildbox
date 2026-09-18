# Open Security Sensor Dockerfile
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

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Install osquery - detect architecture and install accordingly
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then \
        curl -L https://pkg.osquery.io/deb/osquery_5.10.2-1.linux_amd64.deb -o osquery.deb; \
    elif [ "$ARCH" = "arm64" ]; then \
        curl -L https://pkg.osquery.io/deb/osquery_5.10.2-1.linux_arm64.deb -o osquery.deb; \
    else \
        echo "Unsupported architecture: $ARCH" && exit 1; \
    fi && \
    dpkg -i osquery.deb || apt-get install -f -y && \
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
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

# Install the shared package, provided via the `shared` additional build
# context (see docker-compose.yml / CI). --no-deps: its deps already come from
# this service's requirements.txt.
COPY --from=shared . /tmp/open-security-shared
RUN pip install --no-deps /tmp/open-security-shared

# Copy application code
COPY . .

# Install the sensor package
RUN pip install -e .

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
    CMD curl -f http://localhost:8899/health || exit 1

# Expose API port
EXPOSE 8899

# Switch to non-root user
USER sensor

# Set environment variables
ENV PYTHONPATH=/app
ENV SENSOR_LOGGING_LEVEL=INFO
ENV PATH="/usr/local/bin:/usr/bin:/bin:$PATH"

# Run the sensor
CMD ["python", "main.py", "--config", "/etc/security-sensor/config.yaml"]
