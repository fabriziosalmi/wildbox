FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

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
