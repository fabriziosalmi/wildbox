#!/bin/bash

# Setup script for Open Security Identity service
# This script automates the initial setup and configuration

set -e

echo "🎯 Open Security Ident    echo "   ht    echo "📖 Documentation: http://localhost:8001/docs"p://localhost:8001/docs"ty - Setup Script"
echo "========================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Check if Docker is running
check_docker() {
    if ! docker info >/dev/null 2>&1; then
        error "Docker is not running. Please start Docker and try again."
        exit 1
    fi
    log "Docker is running ✓"
}

# Check if docker-compose is available
check_docker_compose() {
    if ! command -v docker-compose >/dev/null 2>&1; then
        error "docker-compose is not installed. Please install it and try again."
        exit 1
    fi
    log "docker-compose is available ✓"
}

# Generate secure secrets
generate_secrets() {
    log "Generating secure secrets..."
    
    # Generate JWT secret
    JWT_SECRET=$(openssl rand -hex 32)
    
    # Generate a secure API key for testing
    TEST_API_KEY=$(openssl rand -hex 32)
    
    log "Secrets generated ✓"
}

# Setup environment file
setup_environment() {
    log "Setting up environment configuration..."
    
    if [[ ! -f .env ]]; then
        cp .env.example .env
        log "Created .env from template"
    else
        warn ".env file already exists, skipping"
        return
    fi
    
    # Update with generated secrets
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        sed -i '' "s/your-super-secret-jwt-key-change-in-production/$JWT_SECRET/" .env
    else
        # Linux
        sed -i "s/your-super-secret-jwt-key-change-in-production/$JWT_SECRET/" .env
    fi
    
    log "Environment configured with secure secrets ✓"
}

# Create necessary directories
create_directories() {
    log "Creating necessary directories..."
    
    mkdir -p logs
    mkdir -p tests/data
    
    log "Directories created ✓"
}

# Install Python dependencies (if running locally)
install_dependencies() {
    if [[ "$1" == "local" ]]; then
        log "Installing Python dependencies..."
        
        if command -v pip >/dev/null 2>&1; then
            pip install -r requirements.txt
            log "Dependencies installed ✓"
        else
            warn "pip not found, skipping dependency installation"
        fi
    fi
}

# Start services with Docker
start_services() {
    log "Starting services with Docker Compose..."
    
    # Build and start services
    docker-compose up -d --build
    
    # Wait for database to be ready
    log "Waiting for database to be ready..."
    sleep 10
    
    # Run migrations
    log "Running database migrations..."
    docker-compose exec -T identity alembic upgrade head
    
    log "Services started successfully ✓"
}

# Run tests
run_tests() {
    log "Running basic tests..."
    
    # Wait a bit more for services to be fully ready
    sleep 5
    
    # Test the health endpoint
    if curl -f http://localhost:8001/health >/dev/null 2>&1; then
        log "Health check passed ✓"
    else
        warn "Health check failed - service may still be starting"
    fi
}

# Show usage information
show_usage() {
    echo ""
    info "Setup completed successfully!"
    echo ""
    echo "🚀 Next steps:"
    echo ""
    echo "1. Check service status:"
    echo "   make status"
    echo ""
    echo "2. View logs:"
    echo "   make logs"
    echo ""
    echo "3. Access the API documentation:"
    echo "   http://localhost:8000/docs"
    echo ""
    echo "4. Run the demo script:"
    echo "   python demo.py"
    echo ""
    echo "5. Run tests:"
    echo "   make test"
    echo ""
    echo "📋 Useful commands:"
    echo "   make dev      - Start development environment"
    echo "   make prod     - Start production environment"
    echo "   make stop     - Stop all services"
    echo "   make clean    - Clean up containers and volumes"
    echo "   make shell    - Open shell in identity container"
    echo ""
    echo "📖 Documentation: http://localhost:8000/docs"
    echo "🔗 Repository: https://github.com/fabriziosalmi/wildbox"
    echo ""
}

# Main setup function
main() {
    local mode=${1:-docker}
    
    echo "Setting up Open Security Identity service..."
    echo "Mode: $mode"
    echo ""
    
    # Run setup steps
    check_docker
    check_docker_compose
    generate_secrets
    setup_environment
    create_directories
    
    if [[ "$mode" == "local" ]]; then
        install_dependencies local
        log "Local setup completed. Start with: uvicorn app.main:app --reload"
    else
        start_services
        run_tests
    fi
    
    show_usage
}

# Parse command line arguments
case "${1:-}" in
    "local")
        main local
        ;;
    "docker"|"")
        main docker
        ;;
    "help"|"-h"|"--help")
        echo "Usage: $0 [local|docker]"
        echo ""
        echo "  local   - Setup for local development (no Docker)"
        echo "  docker  - Setup with Docker Compose (default)"
        echo ""
        exit 0
        ;;
    *)
        error "Unknown option: $1"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac
