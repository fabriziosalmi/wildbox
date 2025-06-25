# Wildbox Security Dashboard - Development Makefile

.PHONY: help install dev build start test lint format type-check clean docker-build docker-dev docker-stop

# Default target
help:
	@echo "Wildbox Security Dashboard - Available Commands:"
	@echo ""
	@echo "Development:"
	@echo "  install      Install dependencies"
	@echo "  dev          Start development server"
	@echo "  build        Build for production"
	@echo "  start        Start production server"
	@echo ""
	@echo "Quality:"
	@echo "  test         Run tests"
	@echo "  lint         Run ESLint"
	@echo "  format       Format code with Prettier"
	@echo "  type-check   Run TypeScript checks"
	@echo ""
	@echo "Docker:"
	@echo "  docker-build Build Docker image"
	@echo "  docker-dev   Start development with Docker"
	@echo "  docker-stop  Stop Docker containers"
	@echo ""
	@echo "Utilities:"
	@echo "  clean        Clean build artifacts"

# Development commands
install:
	npm install

dev:
	npm run dev

build:
	npm run build

start:
	npm run start

# Quality commands
test:
	npm run test

lint:
	npm run lint

format:
	npm run format

type-check:
	npm run type-check

# Docker commands
docker-build:
	docker build -t wildbox-dashboard .

docker-dev:
	docker-compose --profile dev up -d dashboard-dev

docker-prod:
	docker-compose up -d dashboard

docker-stop:
	docker-compose down

docker-logs:
	docker-compose logs -f dashboard

# Utility commands
clean:
	rm -rf .next
	rm -rf node_modules
	rm -rf out
	rm -rf dist

# Setup commands
setup: install
	cp .env.example .env.local
	@echo "✅ Setup complete! Edit .env.local with your configuration."
	@echo "Then run 'make dev' to start development."

# Production deployment
deploy: build
	@echo "🚀 Ready for deployment!"
	@echo "Run 'make start' to start the production server."

# Full development cycle
full-dev: clean install lint type-check dev

# CI/CD pipeline simulation
ci: install lint type-check build
	@echo "✅ CI pipeline completed successfully!"
