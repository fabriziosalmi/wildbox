#!/bin/sh
# Entrypoint script for Open Security Responder
# Starts both Dramatiq worker and FastAPI (uvicorn) server

set -e

echo "Starting Open Security Responder..."
echo "Environment: ${DEBUG:-production}"
echo "Redis URL: ${REDIS_URL}"

# Start Dramatiq worker in background
echo "Starting Dramatiq worker for playbook execution..."
python -m dramatiq app.workflow_engine &
DRAMATIQ_PID=$!
echo "Dramatiq worker started with PID: $DRAMATIQ_PID"

# Wait a moment to ensure worker is ready
sleep 2

# Start uvicorn (FastAPI) in foreground
echo "Starting FastAPI server on 0.0.0.0:8018..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8018
