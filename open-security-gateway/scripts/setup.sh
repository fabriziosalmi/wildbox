#!/bin/bash

# Wildbox Security Gateway Setup Script
# Initializes the gateway for first-time use

set -e

echo "🛡️  Wildbox Security Gateway Setup"
echo "=================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check if Docker is installed and running
check_docker() {
    log_info "Checking Docker installation..."
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        log_error "Docker is not running. Please start Docker first."
        exit 1
    fi
    
    log_success "Docker is installed and running"
}

# Check if Docker Compose is available
check_docker_compose() {
    log_info "Checking Docker Compose..."
    
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    log_success "Docker Compose is available"
}

# Create Docker network
create_network() {
    log_info "Creating Docker network 'wildbox-net'..."
    
    if docker network ls | grep -q wildbox-net; then
        log_warning "Network 'wildbox-net' already exists"
    else
        docker network create wildbox-net
        log_success "Created Docker network 'wildbox-net'"
    fi
}

# Generate SSL certificates
generate_certificates() {
    log_info "Generating SSL certificates..."
    
    if [ -f "$PROJECT_DIR/ssl/wildbox.crt" ] && [ -f "$PROJECT_DIR/ssl/wildbox.key" ]; then
        log_warning "SSL certificates already exist"
        read -p "Do you want to regenerate them? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            return
        fi
    fi
    
    chmod +x "$SCRIPT_DIR/generate_certs.sh"
    "$SCRIPT_DIR/generate_certs.sh"
    log_success "SSL certificates generated"
}

# Setup local hosts file
setup_hosts() {
    log_info "Setting up local DNS entries..."
    
    local hosts_entries=(
        "127.0.0.1 wildbox.local"
        "127.0.0.1 api.wildbox.local" 
        "127.0.0.1 dashboard.wildbox.local"
    )
    
    local hosts_file="/etc/hosts"
    local needs_update=false
    
    for entry in "${hosts_entries[@]}"; do
        if ! grep -q "$(echo "$entry" | cut -d' ' -f2)" "$hosts_file"; then
            needs_update=true
            break
        fi
    done
    
    if [ "$needs_update" = true ]; then
        log_warning "The following entries need to be added to $hosts_file:"
        for entry in "${hosts_entries[@]}"; do
            echo "  $entry"
        done
        echo
        log_warning "Run the following command with sudo privileges:"
        echo "  echo '# Wildbox Security Gateway' | sudo tee -a $hosts_file"
        for entry in "${hosts_entries[@]}"; do
            echo "  echo '$entry' | sudo tee -a $hosts_file"
        done
        echo
        read -p "Press Enter to continue after updating hosts file..."
    else
        log_success "Local DNS entries are already configured"
    fi
}

# Build Docker image
build_image() {
    log_info "Building Docker image..."
    
    cd "$PROJECT_DIR"
    docker build -t wildbox/gateway:latest .
    log_success "Docker image built successfully"
}

# Start services
start_services() {
    log_info "Starting gateway services..."
    
    cd "$PROJECT_DIR"
    docker-compose up -d
    
    # Wait for services to be ready
    log_info "Waiting for services to start..."
    sleep 10
    
    # Check health
    local max_retries=30
    local retry=0
    
    while [ $retry -lt $max_retries ]; do
        if curl -f -s http://localhost/health > /dev/null 2>&1; then
            log_success "Gateway is running and healthy!"
            break
        fi
        
        retry=$((retry + 1))
        if [ $retry -eq $max_retries ]; then
            log_error "Gateway failed to start properly"
            log_info "Check logs with: docker-compose logs gateway"
            exit 1
        fi
        
        sleep 2
    done
}

# Trust SSL certificate on macOS
trust_certificate_macos() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        log_info "Offering to trust SSL certificate on macOS..."
        read -p "Do you want to trust the self-signed certificate? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$PROJECT_DIR/ssl/wildbox.crt"
            log_success "Certificate trusted"
        fi
    fi
}

# Show final information
show_final_info() {
    echo
    echo "🎉 Wildbox Security Gateway Setup Complete!"
    echo "=========================================="
    echo
    echo "🌐 Gateway is now running at:"
    echo "   HTTP:  http://wildbox.local"
    echo "   HTTPS: https://wildbox.local"
    echo
    echo "🔍 Health check:"
    echo "   curl -k https://wildbox.local/health"
    echo
    echo "📋 Useful commands:"
    echo "   make logs     - View logs"
    echo "   make stop     - Stop services"
    echo "   make restart  - Restart services"
    echo "   make shell    - Open shell in container"
    echo
    echo "📚 For more information, see README.md"
    echo
}

# Main setup process
main() {
    echo
    log_info "Starting Wildbox Security Gateway setup..."
    echo
    
    check_docker
    check_docker_compose
    create_network
    generate_certificates
    setup_hosts
    build_image
    start_services
    trust_certificate_macos
    show_final_info
}

# Run main function
main "$@"
