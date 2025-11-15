#!/bin/sh
# Entrypoint script for Open Security Agents
# Starts both Celery worker and FastAPI (uvicorn) server

set -e

echo "Starting Open Security Agents..."
echo "Environment: ${DEBUG:-production}"
echo "Redis URL: ${REDIS_URL}"
echo "OpenAI Model: ${OPENAI_MODEL:-gpt-4o}"

# Start Celery worker in background
echo "Starting Celery worker for AI agent tasks..."
celery -A app.worker worker --loglevel=info --concurrency=2 &
CELERY_PID=$!
echo "Celery worker started with PID: $CELERY_PID"

# Wait a moment to ensure worker is ready
sleep 2

# Start uvicorn (FastAPI) in foreground
echo "Starting FastAPI server on 0.0.0.0:8006..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8006
