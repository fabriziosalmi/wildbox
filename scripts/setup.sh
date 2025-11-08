#!/bin/bash

# Wildbox Setup Script
# One-command deployment script for Wildbox Security Operations Suite
# Usage: ./scripts/setup.sh [dev|prod]

set -e  # Exit on error

# Colors for output
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Configuration
DEPLOYMENT_MODE="${1:-dev}"  # Default to dev mode
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Banner
print_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                                                              ║"
    echo "║              🛡️  Wildbox Setup Script 🛡️                     ║"
    echo "║                                                              ║"
    echo "║    Open-Source Security Operations Suite                    ║"
    echo "║                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Check if running with sudo (should not be)
check_sudo() {
    if [ "$EUID" -eq 0 ]; then
        log_error "Please do not run this script with sudo"
        log_info "The script will request sudo access only when needed"
        exit 1
    fi
}

# Check system requirements
check_requirements() {
    log_info "Checking system requirements..."

    local missing_deps=()

    # Check Docker
    if ! command -v docker &> /dev/null; then
        missing_deps+=("docker")
    else
        log_success "Docker found: $(docker --version | cut -d' ' -f3)"
    fi

    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        missing_deps+=("docker-compose")
    else
        log_success "Docker Compose found: $(docker-compose --version | cut -d' ' -f4)"
    fi

    # Check curl
    if ! command -v curl &> /dev/null; then
        missing_deps+=("curl")
    else
        log_success "curl found"
    fi

    # Check make (optional but recommended)
    if ! command -v make &> /dev/null; then
        log_warning "make not found (optional, but recommended)"
    else
        log_success "make found"
    fi

    # Report missing dependencies
    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        echo ""
        echo "Please install the missing dependencies:"
        echo ""
        echo "Ubuntu/Debian:"
        echo "  sudo apt-get update"
        echo "  sudo apt-get install -y docker.io docker-compose curl make"
        echo ""
        echo "macOS:"
        echo "  brew install docker docker-compose curl"
        echo ""
        echo "See https://docs.docker.com/get-docker/ for more details"
        exit 1
    fi

    log_success "All requirements met"
}

# Generate random secret
generate_secret() {
    local length=${1:-32}
    if command -v openssl &> /dev/null; then
        openssl rand -hex "$length"
    else
        head -c "$length" /dev/urandom | base64 | tr -d '/+=\n' | cut -c1-$((length*2))
    fi
}

# Setup environment file
setup_environment() {
    log_info "Setting up environment configuration..."

    cd "$PROJECT_ROOT"

    if [ -f .env ]; then
        log_warning ".env file already exists"
        read -p "Do you want to backup and recreate it? (y/N) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            backup_file=".env.backup.$(date +%Y%m%d_%H%M%S)"
            cp .env "$backup_file"
            log_success "Backed up existing .env to $backup_file"
        else
            log_info "Keeping existing .env file"
            return 0
        fi
    fi

    if [ ! -f .env.example ]; then
        log_error ".env.example not found"
        exit 1
    fi

    # Copy example file
    cp .env.example .env

    # Generate secure secrets for production
    if [ "$DEPLOYMENT_MODE" = "prod" ]; then
        log_info "Generating secure secrets for production..."

        # Generate JWT secret
        jwt_secret=$(generate_secret 32)
        sed -i.bak "s|JWT_SECRET_KEY=.*|JWT_SECRET_KEY=$jwt_secret|" .env

        # Generate API key
        api_key=$(generate_secret 32)
        sed -i.bak "s|API_KEY=.*|API_KEY=$api_key|" .env

        # Generate database password
        db_password=$(generate_secret 16)
        sed -i.bak "s|postgres:postgres@|postgres:$db_password@|" .env

        # Clean up backup files
        rm -f .env.bak

        log_success "Secure secrets generated"
        log_warning "Please review and update .env with your specific values"
    else
        log_info "Using development defaults from .env.example"
        log_warning "For production, run: ./scripts/setup.sh prod"
    fi

    log_success "Environment file created: .env"
}

# Setup Docker network
setup_network() {
    log_info "Setting up Docker network..."

    if docker network inspect wildbox &> /dev/null; then
        log_success "Docker network 'wildbox' already exists"
    else
        docker network create wildbox
        log_success "Docker network 'wildbox' created"
    fi
}

# Pull and build images
build_images() {
    log_info "Building Docker images (this may take several minutes)..."

    cd "$PROJECT_ROOT"

    if [ "$DEPLOYMENT_MODE" = "prod" ]; then
        docker-compose -f docker-compose.yml build --parallel
    else
        docker-compose build --parallel
    fi

    log_success "Docker images built successfully"
}

# Start services
start_services() {
    log_info "Starting services..."

    cd "$PROJECT_ROOT"

    if [ "$DEPLOYMENT_MODE" = "prod" ]; then
        docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
    else
        docker-compose up -d
    fi

    log_success "Services started"
}

# Wait for services to be ready
wait_for_services() {
    log_info "Waiting for services to be ready..."

    local max_attempts=60
    local attempt=0

    while [ $attempt -lt $max_attempts ]; do
        if curl -sf http://localhost:8000/health > /dev/null 2>&1; then
            log_success "Services are ready!"
            return 0
        fi

        attempt=$((attempt + 1))
        echo -n "."
        sleep 2
    done

    echo ""
    log_error "Services did not become ready in time"
    log_info "Check logs with: docker-compose logs"
    return 1
}

# Run database migrations
run_migrations() {
    log_info "Running database migrations..."

    cd "$PROJECT_ROOT"

    # Wait a bit more to ensure databases are ready
    sleep 5

    # Run migrations for each service
    docker-compose exec -T identity alembic upgrade head 2>/dev/null || log_warning "Identity migrations skipped"
    docker-compose exec -T guardian python manage.py migrate 2>/dev/null || log_warning "Guardian migrations skipped"

    log_success "Migrations completed"
}

# Display final information
show_completion_info() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                              ║${NC}"
    echo -e "${GREEN}║              ✓ Wildbox Setup Complete! ✓                     ║${NC}"
    echo -e "${GREEN}║                                                              ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}Access Points:${NC}"
    echo "  🖥️  Dashboard:    http://localhost:3000"
    echo "  🔌 API Gateway:  http://localhost:8080"
    echo "  📖 API Docs:     http://localhost:8000/docs"
    echo ""
    echo -e "${BLUE}Useful Commands:${NC}"
    echo "  make health      - Check service health"
    echo "  make logs        - View service logs"
    echo "  make stop        - Stop all services"
    echo "  make restart     - Restart all services"
    echo ""

    if [ "$DEPLOYMENT_MODE" = "dev" ]; then
        echo -e "${YELLOW}Default Credentials (Development Only):${NC}"
        echo "  Email:    admin@wildbox.local"
        echo "  Password: admin123"
        echo ""
        echo -e "${RED}⚠️  IMPORTANT: Change default credentials before production!${NC}"
    else
        echo -e "${YELLOW}Production Deployment:${NC}"
        echo "  1. Review .env for all configurations"
        echo "  2. Set up SSL/TLS certificates"
        echo "  3. Configure firewall rules"
        echo "  4. Enable monitoring and logging"
        echo ""
        echo "See docs/guides/deployment.md for complete production checklist"
    fi

    echo ""
    echo -e "${GREEN}For more information:${NC}"
    echo "  📖 Documentation: https://www.wildbox.io"
    echo "  💬 GitHub:        https://github.com/fabriziosalmi/wildbox"
    echo ""
}

# Cleanup on error
cleanup_on_error() {
    log_error "Setup failed. Cleaning up..."
    docker-compose down 2>/dev/null || true
    exit 1
}

# Main setup flow
main() {
    print_banner

    # Validate deployment mode
    if [[ ! "$DEPLOYMENT_MODE" =~ ^(dev|prod)$ ]]; then
        log_error "Invalid deployment mode: $DEPLOYMENT_MODE"
        echo "Usage: $0 [dev|prod]"
        exit 1
    fi

    log_info "Deployment mode: $DEPLOYMENT_MODE"
    echo ""

    # Set up error handler
    trap cleanup_on_error ERR

    # Run setup steps
    check_sudo
    check_requirements
    echo ""

    setup_environment
    echo ""

    setup_network
    echo ""

    build_images
    echo ""

    start_services
    echo ""

    wait_for_services
    echo ""

    run_migrations
    echo ""

    show_completion_info
}

# Run main function
main "$@"
