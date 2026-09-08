# Wildbox Security Platform - Simplified Makefile
# Use Docker Compose for orchestration - this is just a convenience wrapper

.PHONY: help setup generate-secrets validate-secrets start start-prod stop restart logs health test clean backup restore-drill rotate-secrets lock

# Colors
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m

help:
	@echo "$(BLUE)Wildbox Security Platform$(NC)"
	@echo ""
	@echo "$(GREEN)Essential Commands:$(NC)"
	@echo "  make setup            - First-time setup (copy .env, validate config)"
	@echo "  make generate-secrets - Generate a .env with secure random secrets"
	@echo "  make validate-secrets - Check .env for insecure/default values"
	@echo "  make start    - Start all services"
	@echo "  make stop     - Stop all services"
	@echo "  make restart  - Restart all services"
	@echo "  make logs     - Follow logs (ctrl+c to exit)"
	@echo "  make health   - Run health checks"
	@echo "  make test     - Run integration tests"
	@echo "  make clean    - Remove temp files and caches"
	@echo ""
	@echo "$(YELLOW)Advanced:$(NC)"
	@echo "  docker-compose build          - Rebuild images"
	@echo "  docker-compose ps             - Service status"
	@echo "  docker-compose exec [service] - Shell into service"
	@echo "  ./scripts/shell-scripts/comprehensive_health_check.sh - Full diagnostics"
	@echo ""
	@echo "$(YELLOW)First time? Run: make setup && make start$(NC)"

setup:
	@echo "$(BLUE)Setting up Wildbox...$(NC)"
	@if [ ! -f .env ]; then \
		cp .env.example .env && \
		echo "$(GREEN)✓ Created .env from template$(NC)" && \
		echo "$(RED)⚠️  EDIT .env AND SET SECURE PASSWORDS!$(NC)"; \
	else \
		echo "$(GREEN)✓ .env already exists$(NC)"; \
	fi
	@./scripts/shell-scripts/validate_env.sh
	@echo ""
	@echo "$(GREEN)✓ Setup complete!$(NC)"
	@echo "Next: make start"

generate-secrets:
	@echo "$(BLUE)Generating .env with secure secrets...$(NC)"
	@python3 scripts/generate_secrets.py

validate-secrets:
	@echo "$(BLUE)Validating .env secrets...$(NC)"
	@python3 scripts/validate_secrets.py

# `start` composes base + dev overlay EXPLICITLY.
#
# docker-compose.override.yml is Compose's automatic overlay: it applied with no
# flag, so `make start` silently merged a file headed "Development Integration"
# -- and dropped the prod overlay's restart: always, log rotation and resource
# limits -- on every restart after setup.sh had done the right thing
# (WILDBO-OPS-01). Both paths are now named in the command that is typed.
COMPOSE_DEV  := -f docker-compose.yml -f docker-compose.dev.yml
COMPOSE_PROD := -f docker-compose.yml -f docker-compose.prod.yml

start: validate-secrets
	@echo "$(BLUE)Starting services (development configuration)...$(NC)"
	@docker-compose $(COMPOSE_DEV) up -d
	@echo "$(YELLOW)Waiting for services...$(NC)"
	@sleep 15
	@echo ""
	@echo "$(GREEN)✓ Services started$(NC)"
	@echo "  Dashboard: http://localhost:3000"
	@echo "  Gateway:   http://localhost"
	@echo ""
	@echo "Check status: make health"

start-prod: validate-secrets
	@echo "$(BLUE)Starting services (production configuration)...$(NC)"
	@docker-compose $(COMPOSE_PROD) up -d
	@echo "$(YELLOW)Waiting for services...$(NC)"
	@sleep 15
	@echo "$(GREEN)✓ Services started with docker-compose.prod.yml$(NC)"
	@echo "Check status: make health"

backup:
	@echo "$(BLUE)Backing up PostgreSQL and Redis...$(NC)"
	@./scripts/backup_postgres.sh

restore-drill:
	@echo "$(BLUE)Running the restore drill (backup -> restore -> verify)...$(NC)"
	@./scripts/verify_restore.sh

rotate-secrets:
	@./scripts/rotate_secrets.sh --list

lock:
	@echo "$(BLUE)Compiling hash-pinned lockfiles for every service...$(NC)"
	@./scripts/compile_requirements.sh

stop:
	@docker-compose down
	@echo "$(GREEN)✓ Services stopped$(NC)"

restart:
	@docker-compose restart
	@echo "$(GREEN)✓ Services restarted$(NC)"

logs:
	@docker-compose logs -f

health:
	@./scripts/shell-scripts/comprehensive_health_check.sh

test:
	@echo "$(BLUE)Running integration tests...$(NC)"
	@docker-compose exec -T identity pytest tests/
	@docker-compose exec -T guardian python manage.py test
	@echo "$(GREEN)✓ Tests complete$(NC)"

clean:
	@echo "$(BLUE)Cleaning...$(NC)"
	@find . -type f -name "*.pyc" -delete
	@find . -type d -name "__pycache__" -delete
	@find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	@docker system prune -f --volumes
	@echo "$(GREEN)✓ Cleanup complete$(NC)"
