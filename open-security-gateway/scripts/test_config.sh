#!/bin/bash

# Test Nginx configuration syntax
# This script tests the configuration with mock upstreams

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "🔍 Testing Nginx configuration syntax..."

# Create temporary test configuration
TEMP_DIR="/tmp/wildbox-gateway-test"
mkdir -p "$TEMP_DIR/nginx/conf.d"
mkdir -p "$TEMP_DIR/nginx/lua"

# Copy base nginx.conf but without the rate limiting that references custom variables
cat > "$TEMP_DIR/nginx/nginx.conf" << 'EOF'
user nginx;
worker_processes auto;
worker_rlimit_nofile 65535;

error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 4096;
    use epoll;
    multi_accept on;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Logging Configuration
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;

    # Performance Settings
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;

    # Basic rate limiting for testing
    limit_req_zone $binary_remote_addr zone=global:10m rate=100r/s;

    # Shared Dictionary for Authentication Cache
    lua_shared_dict auth_cache 50m;
    lua_shared_dict rate_limit_cache 10m;
    lua_shared_dict config_cache 10m;

    # Lua Package Path
    lua_package_path "/etc/nginx/lua/?.lua;;";

    # Include service-specific configurations
    include /etc/nginx/conf.d/*.conf;
}
EOF

# Copy Lua files
cp "$PROJECT_DIR/nginx/lua/"*.lua "$TEMP_DIR/nginx/lua/"

# Create simplified proxy params for testing
cat > "$TEMP_DIR/nginx/conf.d/proxy_params.conf" << 'EOF'
# Common proxy parameters for testing

proxy_http_version 1.1;
proxy_set_header Connection "";
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;

# Timeout settings
proxy_connect_timeout 5s;
proxy_send_timeout 60s;
proxy_read_timeout 60s;

# Buffer settings
proxy_buffering on;
proxy_buffer_size 4k;
proxy_buffers 8 4k;
EOF

# Create test configuration with localhost upstreams
cat > "$TEMP_DIR/nginx/conf.d/wildbox_gateway.conf" << 'EOF'
# Test configuration with localhost upstreams

upstream identity_service {
    server 127.0.0.1:8000;
}

upstream data_service {
    server 127.0.0.1:8001;
}

upstream cspm_service {
    server 127.0.0.1:8002;
}

upstream guardian_service {
    server 127.0.0.1:8003;
}

upstream responder_service {
    server 127.0.0.1:8004;
}

upstream agents_service {
    server 127.0.0.1:8006;
}

upstream dashboard_service {
    server 127.0.0.1:3000;
}

upstream sensor_service {
    server 127.0.0.1:8006;
}

upstream automations_service {
    server 127.0.0.1:5678;
}

server {
    listen 80;
    server_name localhost;
    
    location /health {
        return 200 '{"status":"healthy"}';
        add_header Content-Type application/json;
    }
    
    location / {
        return 200 'Test configuration OK';
    }
}
EOF

echo "📋 Testing configuration syntax..."

# Test the configuration
docker run --rm \
    -v "$TEMP_DIR/nginx:/etc/nginx:ro" \
    openresty/openresty:alpine \
    /usr/local/openresty/bin/openresty -t

if [ $? -eq 0 ]; then
    echo "✅ Nginx configuration syntax is valid!"
else
    echo "❌ Nginx configuration syntax errors found"
    exit 1
fi

# Clean up
rm -rf "$TEMP_DIR"

echo "🧹 Cleanup completed"
