#!/bin/sh
# Entrypoint script for Open Security Responder
# Starts both Dramatiq worker and FastAPI (uvicorn) server

set -e

# Nothing of REDIS_URL is printed: in the stack it carries the Redis
# password, and this line wrote it to the container's log at every start.
# ENVIRONMENT is what decides development or not; the line said
# "Environment: false", the value of DEBUG.
echo "Starting Open Security Responder..."
echo "Environment: ${ENVIRONMENT:-not set}"

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
