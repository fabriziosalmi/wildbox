# Wildbox - Open-Source Security Operations Suite
# Main Makefile for orchestrating all services

.PHONY: help setup install dev test clean docker-build docker-up docker-down logs health \
	setup-dev setup-prod deploy start stop restart status security-check update backup

# Colors for output
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m # No Color

# Default target
help:
	@echo "$(BLUE)Wildbox - Open-Source Security Operations Suite$(NC)"
	@echo ""
	@echo "$(GREEN)Quick Start Commands:$(NC)"
	@echo "  make setup          - Complete setup (development environment)"
	@echo "  make start          - Start all services"
	@echo "  make stop           - Stop all services"
	@echo "  make logs           - View logs from all services"
	@echo "  make health         - Check health of all services"
	@echo ""
	@echo "$(GREEN)Development Commands:$(NC)"
	@echo "  make install        - Install dependencies for all services"
	@echo "  make dev            - Run in development mode"
	@echo "  make test           - Run tests for all services"
	@echo "  make clean          - Clean temporary files and caches"
	@echo ""
	@echo "$(GREEN)Docker Commands:$(NC)"
	@echo "  make docker-build   - Build all Docker images"
	@echo "  make docker-up      - Start all Docker services"
	@echo "  make docker-down    - Stop all Docker services"
	@echo "  make restart        - Restart all services"
	@echo "  make status         - Show status of all services"
	@echo ""
	@echo "$(GREEN)Deployment Commands:$(NC)"
	@echo "  make setup-prod     - Setup production environment"
	@echo "  make deploy         - Deploy to production"
	@echo "  make backup         - Backup databases and configs"
	@echo ""
	@echo "$(GREEN)Maintenance Commands:$(NC)"
	@echo "  make update         - Update all dependencies"
	@echo "  make security-check - Run security audits"
	@echo "  make migrate        - Run database migrations"
	@echo ""
	@echo "$(YELLOW)For more details, see README.md and docs/$(NC)"

# Complete setup for development
setup: setup-dev
	@echo "$(GREEN)✓ Setup complete!$(NC)"
	@echo ""
	@echo "Next steps:"
	@echo "  1. Edit .env and set secure values for all secrets"
	@echo "  2. Run 'make start' to start all services"
	@echo "  3. Visit http://localhost:3000 for the dashboard"
	@echo "  4. See docs/guides/quickstart.md for more info"

# Development setup
setup-dev:
	@echo "$(BLUE)Setting up Wildbox development environment...$(NC)"
	@if [ ! -f .env ]; then \
		echo "$(YELLOW)Creating .env from .env.example...$(NC)"; \
		cp .env.example .env; \
		echo "$(RED)⚠️  IMPORTANT: Edit .env and set secure values!$(NC)"; \
	else \
		echo "$(GREEN)✓ .env already exists$(NC)"; \
	fi
	@echo "$(YELLOW)Validating .env configuration...$(NC)"
	@./validate_env.sh || exit 1
	@echo "$(GREEN)✓ Environment file ready$(NC)"

# Production setup
setup-prod:
	@echo "$(BLUE)Setting up Wildbox for production...$(NC)"
	@if [ ! -f .env ]; then \
		echo "$(RED)ERROR: .env file not found!$(NC)"; \
		echo "Please create .env with production values"; \
		exit 1; \
	fi
	@echo "$(YELLOW)Validating .env configuration...$(NC)"
	@./validate_env.sh || exit 1
	@echo "$(GREEN)✓ Production setup ready$(NC)"

# Install dependencies for all services
install:
	@echo "$(BLUE)Installing dependencies for all services...$(NC)"
	@for dir in open-security-*/; do \
		if [ -f "$$dir/Makefile" ]; then \
			echo "$(YELLOW)Installing $$dir...$(NC)"; \
			$(MAKE) -C $$dir install; \
		fi; \
	done
	@echo "$(GREEN)✓ All dependencies installed$(NC)"

# Start all services
start: docker-up
	@echo "$(GREEN)✓ All services started$(NC)"
	@echo ""
	@echo "Services available at:"
	@echo "  Dashboard:  http://localhost:3000"
	@echo "  API:        http://localhost:8000/docs"
	@echo "  Gateway:    http://localhost:8080"

# Stop all services
stop: docker-down
	@echo "$(GREEN)✓ All services stopped$(NC)"

# Restart all services
restart:
	@echo "$(BLUE)Restarting all services...$(NC)"
	@$(MAKE) stop
	@sleep 2
	@$(MAKE) start

# Build all Docker images
docker-build:
	@echo "$(BLUE)Building all Docker images...$(NC)"
	@docker-compose build
	@echo "$(GREEN)✓ All images built$(NC)"

# Start all Docker services
docker-up:
	@echo "$(BLUE)Starting all Docker services...$(NC)"
	@echo "$(YELLOW)Validating .env configuration...$(NC)"
	@./validate_env.sh || exit 1
	@docker-compose up -d
	@echo "$(YELLOW)Waiting for services to be ready...$(NC)"
	@sleep 10

# Stop all Docker services
docker-down:
	@echo "$(BLUE)Stopping all Docker services...$(NC)"
	@docker-compose down

# View logs from all services
logs:
	@docker-compose logs -f

# Show service status
status:
	@echo "$(BLUE)Service Status:$(NC)"
	@docker-compose ps

# Health check for all services
health:
	@echo "$(BLUE)Checking health of all services...$(NC)"
	@echo ""
	@echo "$(YELLOW)Dashboard:$(NC)"
	@curl -sf http://localhost:3000 > /dev/null && echo "$(GREEN)✓ OK$(NC)" || echo "$(RED)✗ DOWN$(NC)"
	@echo ""
	@echo "$(YELLOW)API Gateway:$(NC)"
	@curl -sf http://localhost:8080/health > /dev/null && echo "$(GREEN)✓ OK$(NC)" || echo "$(RED)✗ DOWN$(NC)"
	@echo ""
	@echo "$(YELLOW)Identity Service:$(NC)"
	@curl -sf http://localhost:8001/health > /dev/null && echo "$(GREEN)✓ OK$(NC)" || echo "$(RED)✗ DOWN$(NC)"
	@echo ""
	@echo "$(YELLOW)Tools Service:$(NC)"
	@curl -sf http://localhost:8002/health > /dev/null && echo "$(GREEN)✓ OK$(NC)" || echo "$(RED)✗ DOWN$(NC)"
	@echo ""
	@echo "$(YELLOW)Data Service:$(NC)"
	@curl -sf http://localhost:8003/health > /dev/null && echo "$(GREEN)✓ OK$(NC)" || echo "$(RED)✗ DOWN$(NC)"

# Run tests for all services
test:
	@echo "$(BLUE)Running tests for all services...$(NC)"
	@failed=0; \
	for dir in open-security-*/; do \
		if [ -f "$$dir/Makefile" ] && grep -q "^test:" "$$dir/Makefile"; then \
			echo "$(YELLOW)Testing $$dir...$(NC)"; \
			if ! $(MAKE) -C $$dir test; then \
				echo "$(RED)✗ Tests failed in $$dir$(NC)"; \
				failed=1; \
			fi; \
		fi; \
	done; \
	if [ $$failed -eq 1 ]; then \
		echo "$(RED)✗ Some tests failed$(NC)"; \
		exit 1; \
	fi
	@echo "$(GREEN)✓ All tests passed$(NC)"

# Clean temporary files
clean:
	@echo "$(BLUE)Cleaning temporary files...$(NC)"
	@for dir in open-security-*/; do \
		if [ -f "$$dir/Makefile" ] && grep -q "^clean:" "$$dir/Makefile"; then \
			echo "$(YELLOW)Cleaning $$dir...$(NC)"; \
			$(MAKE) -C $$dir clean; \
		fi; \
	done
	@find . -type f -name "*.pyc" -delete
	@find . -type d -name "__pycache__" -delete
	@find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name "node_modules/.cache" -exec rm -rf {} + 2>/dev/null || true
	@echo "$(GREEN)✓ Cleanup complete$(NC)"

# Update all dependencies
update:
	@echo "$(BLUE)Updating all dependencies...$(NC)"
	@echo "$(YELLOW)Pulling latest images...$(NC)"
	@docker-compose pull
	@echo "$(YELLOW)Updating Python packages...$(NC)"
	@for dir in open-security-*/; do \
		if [ -f "$$dir/requirements.txt" ]; then \
			echo "Updating $$dir..."; \
			cd $$dir && pip install --upgrade -r requirements.txt && cd ..; \
		fi; \
	done
	@echo "$(GREEN)✓ All dependencies updated$(NC)"

# Run security checks
security-check:
	@echo "$(BLUE)Running security checks...$(NC)"
	@echo ""
	@echo "$(YELLOW)Checking for vulnerable dependencies...$(NC)"
	@failed=0; \
	for dir in open-security-*/; do \
		if [ -f "$$dir/requirements.txt" ]; then \
			echo "Checking $$dir..."; \
			if ! (cd $$dir && pip-audit -r requirements.txt); then \
				echo "$(RED)✗ Vulnerabilities found in $$dir$(NC)"; \
				failed=1; \
			fi; \
		fi; \
	done; \
	if [ $$failed -eq 1 ]; then \
		echo "$(RED)⚠️  Security vulnerabilities detected$(NC)"; \
		exit 1; \
	fi
	@echo ""
	@echo "$(YELLOW)Checking Docker image vulnerabilities...$(NC)"
	@command -v trivy >/dev/null 2>&1 && trivy image --severity HIGH,CRITICAL wildbox || \
		echo "$(YELLOW)Install trivy for Docker security scanning$(NC)"
	@echo "$(GREEN)✓ Security check complete$(NC)"

# Database migrations
migrate:
	@echo "$(BLUE)Running database migrations...$(NC)"
	@docker-compose exec -T identity alembic upgrade head || echo "$(YELLOW)Identity migrations skipped$(NC)"
	@docker-compose exec -T guardian python manage.py migrate || echo "$(YELLOW)Guardian migrations skipped$(NC)"
	@echo "$(GREEN)✓ Migrations complete$(NC)"

# Backup databases and configurations
backup:
	@echo "$(BLUE)Creating backup...$(NC)"
	@mkdir -p backups
	@timestamp=$$(date +%Y%m%d_%H%M%S); \
	docker-compose exec -T postgres pg_dumpall -U postgres > backups/postgres_$$timestamp.sql && \
		echo "$(GREEN)✓ Database backup created: backups/postgres_$$timestamp.sql$(NC)" || \
		echo "$(RED)✗ Database backup failed$(NC)"
	@cp .env backups/.env_$$(date +%Y%m%d_%H%M%S) 2>/dev/null && \
		echo "$(GREEN)✓ Environment backup created$(NC)" || true

# Deploy to production
deploy: setup-prod docker-build
	@echo "$(BLUE)Deploying to production...$(NC)"
	@docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
	@echo "$(YELLOW)Running migrations...$(NC)"
	@$(MAKE) migrate
	@echo "$(GREEN)✓ Deployment complete$(NC)"
	@echo ""
	@echo "$(YELLOW)Post-deployment checklist:$(NC)"
	@echo "  1. Verify all services are healthy: make health"
	@echo "  2. Check logs for errors: make logs"
	@echo "  3. Run security check: make security-check"
	@echo "  4. Create backup: make backup"

# Development workflow
dev:
	@echo "$(BLUE)Starting development environment...$(NC)"
	@docker-compose -f docker-compose.yml -f docker-compose.override.yml up

# Quick rebuild and restart
rebuild:
	@echo "$(BLUE)Rebuilding and restarting services...$(NC)"
	@docker-compose down
	@docker-compose build
	@docker-compose up -d
	@echo "$(GREEN)✓ Services rebuilt and restarted$(NC)"
