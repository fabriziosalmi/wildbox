# Open Security CSPM - Makefile

.PHONY: help install dev build test lint format clean docker-build docker-up docker-down logs

# Colors 	docker run --rm -d --name cspm-test -p 8019:8019 wildbox/cspm:latest
	@sleep 5
	@curl -f http://localhost:8019/health || (echo "$(RED)Health check failed$(NC)" && exit 1) terminal output
RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[1;33m
NC = \033[0m # No Color

help: ## Show this help message
	@echo "$(GREEN)Open Security CSPM - Available Commands:$(NC)"
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ { printf "  $(YELLOW)%-15s$(NC) %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

install: ## Install Python dependencies
	@echo "$(YELLOW)Installing dependencies...$(NC)"
	pip install -r requirements.txt

dev: docker-up ## Start development environment
	@echo "$(GREEN)CSPM Services started:$(NC)"
	@echo "  - CSPM API: http://localhost:8006"
	@echo "  - API Documentation: http://localhost:8006/docs"
	@echo "  - Flower (Celery Monitor): http://localhost:5558"
	@echo "  - Redis: localhost:6385"

build: ## Build the application image
	@echo "$(YELLOW)Building Docker images...$(NC)"
	docker-compose build

test: ## Run tests
	@echo "$(YELLOW)Running tests...$(NC)"
	pytest tests/ -v --cov=app --cov-report=html --cov-report=term

lint: ## Run linting
	@echo "$(YELLOW)Running linting...$(NC)"
	flake8 app/ tests/ --max-line-length=100 --exclude=app/__pycache__,tests/__pycache__
	mypy app/ --ignore-missing-imports

format: ## Format code
	@echo "$(YELLOW)Formatting code...$(NC)"
	black app/ tests/ --line-length=100
	isort app/ tests/ --profile black

clean: ## Clean up
	@echo "$(YELLOW)Cleaning up...$(NC)"
	docker-compose down -v
	docker system prune -f
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf .coverage htmlcov/ .pytest_cache/

docker-build: ## Build Docker images
	@echo "$(YELLOW)Building Docker images...$(NC)"
	docker-compose build

docker-up: ## Start services with Docker Compose
	@echo "$(YELLOW)Starting services...$(NC)"
	docker-compose up -d

docker-down: ## Stop services
	@echo "$(YELLOW)Stopping services...$(NC)"
	docker-compose down

logs: ## View logs
	docker-compose logs -f

status: ## Show container status
	docker-compose ps

# Development workflow
setup: install docker-build ## Setup development environment
	@echo "$(GREEN)Development environment ready!$(NC)"

run-local: ## Run locally without Docker
	@echo "$(YELLOW)Starting local development server...$(NC)"
	uvicorn app.main:app --reload --port 8006

worker: ## Start Celery worker locally
	@echo "$(YELLOW)Starting Celery worker...$(NC)"
	celery -A app.worker worker --loglevel=info --concurrency=4

flower: ## Start Flower for monitoring
	@echo "$(YELLOW)Starting Flower...$(NC)"
	celery -A app.worker flower --port=5555

# Testing specific providers
test-aws: ## Test AWS checks specifically
	@echo "$(YELLOW)Testing AWS checks...$(NC)"
	pytest tests/checks/test_aws* -v

test-gcp: ## Test GCP checks specifically
	@echo "$(YELLOW)Testing GCP checks...$(NC)"
	pytest tests/checks/test_gcp* -v

test-azure: ## Test Azure checks specifically
	@echo "$(YELLOW)Testing Azure checks...$(NC)"
	pytest tests/checks/test_azure* -v

# Database and cache management
redis-cli: ## Connect to Redis CLI
	docker-compose exec redis redis-cli

redis-flush: ## Flush Redis cache
	docker-compose exec redis redis-cli FLUSHALL

# Security and compliance
security-scan: ## Run security scanning on code
	@echo "$(YELLOW)Running security scan...$(NC)"
	bandit -r app/ -f json -o security-report.json
	safety check --json --output safety-report.json

compliance-check: ## Check code compliance
	@echo "$(YELLOW)Checking compliance...$(NC)"
	$(MAKE) lint
	$(MAKE) test
	$(MAKE) security-scan

# Documentation
docs: ## Generate documentation
	@echo "$(YELLOW)Generating documentation...$(NC)"
	python -c "import app.main; import json; print(json.dumps(app.main.app.openapi(), indent=2))" > openapi.json

# Monitoring and metrics
monitor: ## View monitoring info
	@echo "$(GREEN)Monitoring Information:$(NC)"
	@echo "Health Check: curl http://localhost:8006/health"
	@echo "Flower UI: http://localhost:5558"
	@echo "API Docs: http://localhost:8006/docs"

# Production deployment helpers
production-build: ## Build for production
	@echo "$(YELLOW)Building for production...$(NC)"
	docker build -t wildbox/cspm:latest .

production-test: ## Test production build
	@echo "$(YELLOW)Testing production build...$(NC)"
	docker run --rm -d --name cspm-test -p 8007:8006 wildbox/cspm:latest
	@sleep 5
	@curl -f http://localhost:8007/health || (echo "$(RED)Health check failed$(NC)" && exit 1)
	@docker stop csmp-test
	@echo "$(GREEN)Production build test passed$(NC)"

# Example usage and testing
example-scan: ## Run example scan (requires AWS credentials)
	@echo "$(YELLOW)Running example AWS scan...$(NC)"
	curl -X POST "http://localhost:8006/api/v1/scans" \
		 -H "Content-Type: application/json" \
		 -H "Authorization: Bearer dev-token" \
		 -d '{"provider":"aws","credentials":{"auth_method":"access_key","access_key_id":"EXAMPLE","secret_access_key":"EXAMPLE"},"account_id":"123456789012","account_name":"Test Account"}'

list-checks: ## List available checks
	@echo "$(YELLOW)Listing available checks...$(NC)"
	curl -H "Authorization: Bearer dev-token" "http://localhost:8006/api/v1/checks" | jq .

# Quality assurance
qa: format lint test ## Run all quality assurance checks
	@echo "$(GREEN)All QA checks passed!$(NC)"
