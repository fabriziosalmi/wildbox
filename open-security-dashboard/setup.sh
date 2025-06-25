#!/bin/bash

# Wildbox Security Dashboard - Setup Script
# This script sets up the development environment

set -e

echo "🛡️ Wildbox Security Dashboard - Setup Script"
echo "=============================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print functions
print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check if Node.js is installed
check_node() {
    if ! command -v node &> /dev/null; then
        print_error "Node.js is not installed. Please install Node.js 18 or higher."
        exit 1
    fi
    
    NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
    if [ "$NODE_VERSION" -lt 18 ]; then
        print_error "Node.js version 18 or higher is required. Current version: $(node -v)"
        exit 1
    fi
    
    print_success "Node.js $(node -v) is installed"
}

# Check if npm is installed
check_npm() {
    if ! command -v npm &> /dev/null; then
        print_error "npm is not installed. Please install npm."
        exit 1
    fi
    
    print_success "npm $(npm -v) is installed"
}

# Install dependencies
install_dependencies() {
    print_info "Installing dependencies..."
    npm install
    print_success "Dependencies installed successfully"
}

# Setup environment file
setup_env() {
    if [ ! -f .env.local ]; then
        print_info "Creating environment file..."
        cp .env.example .env.local
        print_success "Environment file created: .env.local"
        print_warning "Please edit .env.local with your configuration"
    else
        print_info ".env.local already exists"
    fi
}

# Install additional dependencies for production
install_production_deps() {
    print_info "Installing additional production dependencies..."
    
    # Check if Tailwind CSS Animate plugin is needed
    if ! npm list tailwindcss-animate &> /dev/null; then
        npm install tailwindcss-animate
    fi
    
    # Install missing Radix UI components
    npm install @radix-ui/react-slot
    
    print_success "Additional dependencies installed"
}

# Run type checking
type_check() {
    print_info "Running TypeScript checks..."
    if npm run type-check; then
        print_success "TypeScript checks passed"
    else
        print_warning "TypeScript checks failed, but continuing setup..."
    fi
}

# Run linting
lint_check() {
    print_info "Running ESLint..."
    if npm run lint; then
        print_success "ESLint checks passed"
    else
        print_warning "ESLint checks failed, but continuing setup..."
    fi
}

# Check Docker (optional)
check_docker() {
    if command -v docker &> /dev/null; then
        print_success "Docker is installed"
        if command -v docker-compose &> /dev/null; then
            print_success "Docker Compose is installed"
        else
            print_warning "Docker Compose is not installed (optional)"
        fi
    else
        print_warning "Docker is not installed (optional)"
    fi
}

# Create necessary directories
create_directories() {
    print_info "Creating necessary directories..."
    
    mkdir -p public/icons
    mkdir -p public/images
    mkdir -p src/hooks
    mkdir -p src/utils
    
    print_success "Directories created"
}

# Generate basic favicon
generate_favicon() {
    if [ ! -f public/favicon.ico ]; then
        print_info "Generating basic favicon..."
        # Create a simple SVG favicon
        cat > public/icon.svg << 'EOF'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
  <defs>
    <linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#3B82F6;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#8B5CF6;stop-opacity:1" />
    </linearGradient>
  </defs>
  <rect width="100" height="100" rx="20" fill="url(#grad)"/>
  <path d="M30 50 L45 65 L70 35" stroke="white" stroke-width="6" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
</svg>
EOF
        print_success "Basic favicon generated"
    fi
}

# Print next steps
print_next_steps() {
    echo ""
    echo "🎉 Setup completed successfully!"
    echo ""
    echo "Next steps:"
    echo "1. Edit .env.local with your API endpoints and configuration"
    echo "2. Start the development server: npm run dev"
    echo "3. Open http://localhost:3000 in your browser"
    echo ""
    echo "Available commands:"
    echo "  npm run dev      - Start development server"
    echo "  npm run build    - Build for production"
    echo "  npm run start    - Start production server"
    echo "  npm run lint     - Run ESLint"
    echo "  npm run format   - Format code with Prettier"
    echo ""
    echo "Docker commands (if Docker is installed):"
    echo "  make docker-dev  - Start development with Docker"
    echo "  make docker-prod - Start production with Docker"
    echo ""
    echo "📚 Documentation: See README.md for detailed information"
}

# Main setup process
main() {
    echo ""
    print_info "Starting setup process..."
    echo ""
    
    # Check prerequisites
    check_node
    check_npm
    check_docker
    
    echo ""
    
    # Setup project
    create_directories
    setup_env
    install_dependencies
    install_production_deps
    generate_favicon
    
    echo ""
    
    # Quality checks
    type_check
    lint_check
    
    # Next steps
    print_next_steps
}

# Run main function
main
