FROM python:3.14-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

# Install the shared package, provided via the `shared` additional build
# context (see docker-compose.yml / CI). --no-deps: its deps already come from
# this service's requirements.txt.
COPY --from=shared . /tmp/open-security-shared
RUN pip install --no-deps /tmp/open-security-shared

# Copy application code
COPY . .

# Copy and make scripts executable
COPY scripts/ ./scripts/
RUN chmod +x scripts/*.sh

# Create non-root user
RUN groupadd -r identity && useradd -r -g identity identity
RUN chown -R identity:identity /app
USER identity

# Expose port
EXPOSE 8001

# Use initialization script as entrypoint
CMD ["./scripts/init.sh"]
