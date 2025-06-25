# Open Security Sensor Dockerfile
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    gnupg \
    software-properties-common \
    && rm -rf /var/lib/apt/lists/*

# Install osquery
RUN curl -L https://pkg.osquery.io/deb/osquery_5.10.2-1.linux_amd64.deb -o osquery.deb \
    && dpkg -i osquery.deb || apt-get install -f -y \
    && rm osquery.deb \
    && ln -sf /usr/bin/osqueryd /usr/local/bin/osqueryd \
    && ln -sf /usr/bin/osqueryi /usr/local/bin/osqueryi

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

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
