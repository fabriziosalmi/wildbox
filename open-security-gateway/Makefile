# Wildbox Security Gateway Makefile
# Provides common operations for development and deployment

.PHONY: help build start stop restart logs shell test clean certs network

# Default target
help:
	@echo "🛡️  Wildbox Security Gateway"
	@echo "Available commands:"
	@echo "  make build     - Build the gateway Docker image"
	@echo "  make start     - Start the gateway services"
	@echo "  make stop      - Stop the gateway services"
	@echo "  make restart   - Restart the gateway services"
	@echo "  make logs      - Follow gateway logs"
	@echo "  make shell     - Open shell in gateway container"
	@echo "  make test      - Run gateway tests"
	@echo "  make certs     - Generate SSL certificates"
	@echo "  make network   - Create Docker network"
	@echo "  make clean     - Clean up containers and images"
	@echo "  make config    - Test nginx configuration"
	@echo "  make reload    - Reload nginx configuration"

# Build the Docker image
build:
	@echo "🔨 Building Wildbox Gateway image..."
	docker build -t wildbox/gateway:latest .

# Generate SSL certificates
certs:
	@echo "🔐 Generating SSL certificates..."
	chmod +x scripts/generate_certs.sh
	./scripts/generate_certs.sh

# Create Docker network if it doesn't exist
network:
	@echo "🌐 Creating wildbox-net network..."
	docker network create wildbox-net 2>/dev/null || true

# Start services
start: network certs
	@echo "🚀 Starting Wildbox Gateway..."
	docker-compose up -d
	@echo "✅ Gateway started!"
	@echo "🌐 Access the gateway at:"
	@echo "   HTTP:  http://wildbox.local"
	@echo "   HTTPS: https://wildbox.local"

# Stop services
stop:
	@echo "🛑 Stopping Wildbox Gateway..."
	docker-compose down

# Restart services
restart: stop start

# Follow logs
logs:
	@echo "📋 Following gateway logs..."
	docker-compose logs -f gateway

# Open shell in gateway container
shell:
	@echo "🐚 Opening shell in gateway container..."
	docker-compose exec gateway /bin/sh

# Test nginx configuration
config:
	@echo "🔍 Testing nginx configuration..."
	chmod +x scripts/test_config.sh
	./scripts/test_config.sh

# Reload nginx configuration
reload:
	@echo "🔄 Reloading nginx configuration..."
	docker-compose exec gateway /usr/local/openresty/bin/openresty -s reload

# Run tests
test:
	@echo "🧪 Running gateway tests..."
	chmod +x test/integration_test.sh
	./test/integration_test.sh

# Clean up
clean:
	@echo "🧹 Cleaning up..."
	docker-compose down --volumes --remove-orphans
	docker system prune -f

# Development targets
dev-start: network certs
	@echo "🚀 Starting gateway in development mode..."
	WILDBOX_ENV=development GATEWAY_LOG_LEVEL=debug docker-compose up

dev-logs:
	@echo "📋 Following development logs..."
	docker-compose logs -f

# Check service health
health:
	@echo "🏥 Checking gateway health..."
	@curl -f http://localhost/health && echo "✅ HTTP health check passed" || echo "❌ HTTP health check failed"
	@curl -fk https://localhost/health && echo "✅ HTTPS health check passed" || echo "❌ HTTPS health check failed"

# Show service status
status:
	@echo "📊 Gateway service status:"
	@docker-compose ps

# View real-time metrics
metrics:
	@echo "📈 Real-time gateway metrics:"
	@docker-compose exec gateway tail -f /var/log/nginx/access.log

# Backup configuration
backup:
	@echo "💾 Backing up gateway configuration..."
	@tar -czf gateway-backup-$(shell date +%Y%m%d-%H%M%S).tar.gz nginx/ ssl/ docker-compose.yml
	@echo "✅ Backup created"

# Update gateway
update: stop build start
	@echo "🔄 Gateway updated successfully"
