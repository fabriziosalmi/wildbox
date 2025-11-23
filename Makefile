# Wildbox Security Platform - Simplified Makefile
# Use Docker Compose for orchestration - this is just a convenience wrapper

.PHONY: help setup start stop restart logs health test clean

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
	@echo "  make setup    - First-time setup (copy .env, validate config)"
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

start:
	@echo "$(BLUE)Starting services...$(NC)"
	@docker-compose up -d
	@echo "$(YELLOW)Waiting for services...$(NC)"
	@sleep 15
	@echo ""
	@echo "$(GREEN)✓ Services started$(NC)"
	@echo "  Dashboard: http://localhost:3000"
	@echo "  Gateway:   http://localhost"
	@echo ""
	@echo "Check status: make health"

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
	@docker-compose exec -T identity pytest tests/ || true
	@docker-compose exec -T guardian python manage.py test || true
	@echo "$(GREEN)✓ Tests complete$(NC)"

clean:
	@echo "$(BLUE)Cleaning...$(NC)"
	@find . -type f -name "*.pyc" -delete
	@find . -type d -name "__pycache__" -delete
	@find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	@docker system prune -f --volumes
	@echo "$(GREEN)✓ Cleanup complete$(NC)"
