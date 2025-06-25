# Open Security Agents - Makefile

.PHONY: help install dev test clean docker-build docker-up docker-down logs

# Default target
help:
	@echo "Open Security Agents - Available Commands:"
	@echo ""
	@echo "  make install     - Install Python dependencies"
	@echo "  make dev         - Run development server"
	@echo "  make worker      - Run Celery worker"
	@echo "  make test        - Run tests"
	@echo "  make test-e2e    - Run end-to-end tests"
	@echo "  make clean       - Clean up temporary files"
	@echo ""
	@echo "  make docker-build - Build Docker images"
	@echo "  make docker-up   - Start all services with Docker"
	@echo "  make docker-down - Stop all Docker services"
	@echo "  make logs        - Show Docker logs"
	@echo ""
	@echo "  make redis       - Start Redis server"
	@echo "  make flower      - Start Celery Flower (task monitor)"

# Development setup
install:
	pip install -r requirements.txt

dev:
	uvicorn app.main:app --host 0.0.0.0 --port 8004 --reload

worker:
	celery -A app.worker worker --loglevel=info --concurrency=4

flower:
	celery -A app.worker flower --port=5555

redis:
	redis-server --port 6382

# Testing
test:
	python -m pytest tests/ -v

test-e2e:
	python scripts/test_agents.py

# Docker commands
docker-build:
	docker-compose build

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

docker-logs:
	docker-compose logs -f

logs:
	docker-compose logs -f agents-api

# Cleanup
clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf .pytest_cache/
	rm -rf logs/*.log

# Health checks
health:
	curl -X GET http://localhost:8004/health | jq .

stats:
	curl -X GET http://localhost:8004/stats | jq .

# Development workflow
setup: install
	@echo "Setting up development environment..."
	@echo "1. Copy .env.example to .env"
	@echo "2. Set your OPENAI_API_KEY in .env"
	@echo "3. Run 'make docker-up' to start services"
	@echo "4. Run 'make test-e2e' to verify everything works"

# Production deployment
deploy: docker-build docker-up
	@echo "Deployed to production"
	@echo "API available at http://localhost:8004"
	@echo "Flower UI available at http://localhost:5555"
