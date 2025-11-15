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

# Copy application code
COPY . .

# Create logs directory
RUN mkdir -p logs

# Make entrypoint script executable
RUN chmod +x /app/scripts/entrypoint.sh

# Expose port
EXPOSE 8006

# Use entrypoint script to start both Celery worker and uvicorn
CMD ["/app/scripts/entrypoint.sh"]
