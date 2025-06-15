# Wildbox Security API - Docker Management
# =======================================

.PHONY: help build up down logs shell clean dev prod restart status

# Default target
help:
	@echo "Wildbox Security API - Docker Commands"
	@echo "======================================"
	@echo ""
	@echo "Development:"
	@echo "  dev          - Start development environment with hot reload"
	@echo "  dev-build    - Build and start development environment"
	@echo "  dev-down     - Stop development environment"
	@echo "  dev-logs     - Show development logs"
	@echo ""
	@echo "Production:"
	@echo "  prod         - Start production environment"
	@echo "  prod-build   - Build and start production environment"
	@echo "  prod-down    - Stop production environment"
	@echo "  prod-logs    - Show production logs"
	@echo "  prod-nginx   - Start with Nginx reverse proxy"
	@echo ""
	@echo "Management:"
	@echo "  build        - Build Docker images"
	@echo "  up           - Start services (production)"
	@echo "  down         - Stop all services"
	@echo "  restart      - Restart services"
	@echo "  logs         - Show logs"
	@echo "  shell        - Enter application container shell"
	@echo "  redis-cli    - Enter Redis CLI"
	@echo "  status       - Show container status"
	@echo "  clean        - Remove containers, networks, and volumes"
	@echo "  clean-all    - Remove everything including images"

# Development commands
dev:
	@echo "Starting development environment..."
	@cp .env.example .env 2>/dev/null || true
	@docker-compose -f docker-compose.dev.yml up

dev-build:
	@echo "Building and starting development environment..."
	@cp .env.example .env 2>/dev/null || true
	@docker-compose -f docker-compose.dev.yml up --build

dev-down:
	@docker-compose -f docker-compose.dev.yml down

dev-logs:
	@docker-compose -f docker-compose.dev.yml logs -f

# Production commands
prod:
	@echo "Starting production environment..."
	@docker-compose up -d

prod-build:
	@echo "Building and starting production environment..."
	@docker-compose up --build -d

prod-down:
	@docker-compose down

prod-logs:
	@docker-compose logs -f

prod-nginx:
	@echo "Starting production environment with Nginx..."
	@docker-compose --profile production up -d

# General management
build:
	@docker-compose build

up:
	@docker-compose up -d

down:
	@docker-compose down
	@docker-compose -f docker-compose.dev.yml down

restart:
	@docker-compose restart
	@docker-compose -f docker-compose.dev.yml restart

logs:
	@docker-compose logs -f

shell:
	@docker-compose exec wildbox-api /bin/bash || docker-compose -f docker-compose.dev.yml exec wildbox-api-dev /bin/bash

redis-cli:
	@docker-compose exec redis redis-cli || docker-compose -f docker-compose.dev.yml exec redis redis-cli

status:
	@docker-compose ps
	@echo ""
	@docker-compose -f docker-compose.dev.yml ps

# Cleanup commands
clean:
	@echo "Cleaning up containers, networks, and volumes..."
	@docker-compose down -v --remove-orphans
	@docker-compose -f docker-compose.dev.yml down -v --remove-orphans
	@docker network prune -f
	@docker volume prune -f

clean-all: clean
	@echo "Removing all images..."
	@docker image prune -af
	@docker rmi $(shell docker images "wildbox*" -q) 2>/dev/null || true

# Health checks
health:
	@echo "Checking application health..."
	@curl -f http://localhost:8000/health || echo "Application not responding"

# Setup environment
setup:
	@echo "Setting up environment..."
	@cp .env.example .env
	@echo "Created .env file from .env.example"
	@echo "Please edit .env file with your configuration"

# Show useful URLs
urls:
	@echo "Wildbox Security API URLs:"
	@echo "========================="
	@echo "Web Interface:  http://localhost:8000"
	@echo "API Docs:       http://localhost:8000/docs"
	@echo "ReDoc:          http://localhost:8000/redoc"
	@echo "Health Check:   http://localhost:8000/health"
