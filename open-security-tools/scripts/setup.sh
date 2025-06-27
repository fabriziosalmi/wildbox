#!/bin/bash
# Setup script for Wildbox Security API

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="Wildbox Security API"
REQUIRED_DOCKER_VERSION="20.10.0"
REQUIRED_DOCKER_COMPOSE_VERSION="2.0.0"

# Logging functions
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

# Header
print_header() {
    echo -e "${BLUE}"
    echo "=================================================="
    echo "  $PROJECT_NAME Setup"
    echo "=================================================="
    echo -e "${NC}"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Version comparison function
version_ge() {
    [ "$(printf '%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]
}

# Check Docker installation
check_docker() {
    log "Checking Docker installation..."
    
    if ! command_exists docker; then
        error "Docker is not installed"
        info "Please install Docker from: https://docs.docker.com/get-docker/"
        exit 1
    fi
    
    # Check Docker version
    local docker_version=$(docker --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
    if version_ge "$docker_version" "$REQUIRED_DOCKER_VERSION"; then
        log "Docker $docker_version is installed ✓"
    else
        warn "Docker version $docker_version is older than recommended $REQUIRED_DOCKER_VERSION"
    fi
    
    # Check if Docker daemon is running
    if ! docker info >/dev/null 2>&1; then
        error "Docker daemon is not running"
        info "Please start Docker and try again"
        exit 1
    fi
}

# Check Docker Compose installation
check_docker_compose() {
    log "Checking Docker Compose installation..."
    
    if command_exists docker-compose; then
        local compose_version=$(docker-compose --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
        if version_ge "$compose_version" "$REQUIRED_DOCKER_COMPOSE_VERSION"; then
            log "Docker Compose $compose_version is installed ✓"
        else
            warn "Docker Compose version $compose_version is older than recommended $REQUIRED_DOCKER_COMPOSE_VERSION"
        fi
    elif docker compose version >/dev/null 2>&1; then
        log "Docker Compose (plugin) is installed ✓"
    else
        error "Docker Compose is not installed"
        info "Please install Docker Compose from: https://docs.docker.com/compose/install/"
        exit 1
    fi
}

# Generate secure API key
generate_api_key() {
    if command_exists openssl; then
        openssl rand -hex 32
    elif command_exists python3; then
        python3 -c "import secrets; print(secrets.token_hex(32))"
    else
        # Fallback to random generation
        cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 64 | head -n 1
    fi
}

# Setup environment file
setup_environment() {
    log "Setting up environment configuration..."
    
    if [[ -f .env ]]; then
        warn ".env file already exists"
        read -p "Do you want to overwrite it? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log "Keeping existing .env file"
            return
        fi
    fi
    
    # Copy example file
    cp .env.example .env
    
    # Generate secure API key
    local api_key=$(generate_api_key)
    
    # Update .env file with secure values
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        sed -i '' "s/your-secure-api-key-here-please-change-this-to-something-secure/$api_key/" .env
    else
        # Linux
        sed -i "s/your-secure-api-key-here-please-change-this-to-something-secure/$api_key/" .env
    fi
    
    log "Environment file created with secure API key ✓"
    info "You can modify .env file to customize configuration"
}

# Create necessary directories
create_directories() {
    log "Creating necessary directories..."
    
    mkdir -p logs
    mkdir -p ssl
    
    log "Directories created ✓"
}

# Check system requirements
check_system_requirements() {
    log "Checking system requirements..."
    
    # Check available memory
    if command_exists free; then
        local mem_available=$(free -m | awk 'NR==2{printf "%.0f", $7}')
        if [[ $mem_available -lt 512 ]]; then
            warn "Available memory is low ($mem_available MB). Recommended: 1GB+"
        else
            log "Memory check passed ✓"
        fi
    fi
    
    # Check disk space
    local disk_space=$(df -BG . | awk 'NR==2{print $4}' | sed 's/G//')
    if [[ $disk_space -lt 2 ]]; then
        warn "Available disk space is low (${disk_space}GB). Recommended: 5GB+"
    else
        log "Disk space check passed ✓"
    fi
}

# Test Docker setup
test_docker_setup() {
    log "Testing Docker setup..."
    
    # Test basic Docker functionality
    if docker run --rm hello-world >/dev/null 2>&1; then
        log "Docker test passed ✓"
    else
        error "Docker test failed"
        exit 1
    fi
}

# Display usage information
show_usage() {
    echo ""
    info "Setup completed successfully!"
    echo ""
    echo "Next steps:"
    echo "1. Review and modify .env file if needed"
    echo "2. Start the application:"
    echo ""
    echo "   Development mode:"
    echo -e "   ${GREEN}make dev${NC}"
    echo ""
    echo "   Production mode:"
    echo -e "   ${GREEN}make prod${NC}"
    echo ""
    echo "3. Access the application:"
    echo "   Web Interface: http://localhost:8000"
    echo "   API Docs:      http://localhost:8000/docs"
    echo ""
    echo "Useful commands:"
    echo -e "   ${GREEN}make help${NC}     - Show all available commands"
    echo -e "   ${GREEN}make status${NC}   - Show container status"
    echo -e "   ${GREEN}make logs${NC}     - Show application logs"
    echo -e "   ${GREEN}make shell${NC}    - Enter container shell"
    echo ""
}

# Main setup function
main() {
    print_header
    
    check_docker
    check_docker_compose
    check_system_requirements
    test_docker_setup
    create_directories
    setup_environment
    
    show_usage
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
