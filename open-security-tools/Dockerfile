# Use Python 3.12 slim image for security and performance
FROM python:3.14-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    nmap \
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
    pip install --no-cache-dir -r requirements.txt

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
