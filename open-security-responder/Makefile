# Open Security Responder - Makefile

.PHONY: help install dev test lint format clean docker-build docker-up docker-down logs

# Colors
YELLOW := \033[33m
GREEN := \033[32m
RED := \033[31m
NC := \033[0m # No Color

help: ## Show this help message
	@echo "$(YELLOW)Open Security Responder - Available Commands:$(NC)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(GREEN)%-15s$(NC) %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install: ## Install dependencies
	@echo "$(YELLOW)Installing dependencies...$(NC)"
	pip install -r requirements.txt

dev: ## Start development environment
	@echo "$(YELLOW)Starting development environment...$(NC)"
	docker-compose up -d
	@echo "$(GREEN)Services started:$(NC)"
	@echo "  - Responder API: http://localhost:8003"
	@echo "  - API Documentation: http://localhost:8003/docs"
	@echo "  - Redis: localhost:6381"

test: ## Run tests
	@echo "$(YELLOW)Running tests...$(NC)"
	pytest tests/ -v --cov=app --cov-report=html

lint: ## Run linting
	@echo "$(YELLOW)Running linting...$(NC)"
	flake8 app/ tests/
	mypy app/

format: ## Format code
	@echo "$(YELLOW)Formatting code...$(NC)"
	black app/ tests/
	isort app/ tests/

clean: ## Clean up
	@echo "$(YELLOW)Cleaning up...$(NC)"
	docker-compose down
	docker system prune -f
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

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

# Development workflow
setup: install docker-build ## Setup development environment
	@echo "$(GREEN)Development environment ready!$(NC)"

run-local: ## Run locally without Docker
	@echo "$(YELLOW)Starting local development server...$(NC)"
	uvicorn app.main:app --reload --port 8003

worker: ## Start Dramatiq worker locally
	@echo "$(YELLOW)Starting Dramatiq worker...$(NC)"
	python -m dramatiq app.workflow_engine -p 4 -t 4

test-playbook: ## Test example playbook
	@echo "$(YELLOW)Testing example playbook...$(NC)"
	python scripts/test_responder.py
