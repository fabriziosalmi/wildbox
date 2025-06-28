.PHONY: help setup dev prod test clean build logs shell migrate-only

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

setup: ## Quick setup with automatic migration (recommended)
	./scripts/setup.sh

dev: ## Start development environment with auto-migration
	docker-compose up --build

prod: ## Start production environment
	docker-compose -f docker-compose.yml up -d --build

migrate-only: ## Run only database migrations (manual)
	docker-compose exec identity alembic upgrade head

test: ## Run tests
	docker-compose exec identity pytest

logs: ## Show application logs
	docker-compose logs -f identity

shell: ## Open shell in identity container
	docker-compose exec identity bash

db-migrate: ## Run database migrations (legacy - use 'make migrate-only')
	docker-compose exec identity alembic upgrade head

db-reset: ## Reset database (WARNING: destroys all data)
	docker-compose down -v
	docker-compose up -d postgres redis
	sleep 5
	docker-compose exec identity alembic upgrade head

stop: ## Stop all services
	docker-compose down

clean: ## Clean up containers and volumes
	docker-compose down -v --remove-orphans
	docker system prune -f

build: ## Build the application image
	docker-compose build

status: ## Show container status
	docker-compose ps

format: ## Format code with black and isort
	black app/ tests/
	isort app/ tests/

lint: ## Lint code with flake8
	flake8 app/ tests/

type-check: ## Check types with mypy
	mypy app/

quality: format lint type-check ## Run all code quality checks
