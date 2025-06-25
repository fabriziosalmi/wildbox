#!/bin/bash

# Generate SSL certificates for Wildbox Gateway development
# This script creates self-signed certificates for local development

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSL_DIR="$(dirname "$SCRIPT_DIR")/ssl"
DOMAIN="wildbox.local"

echo "🔐 Generating SSL certificates for Wildbox Gateway..."

# Create SSL directory if it doesn't exist
mkdir -p "$SSL_DIR"

# Generate private key
echo "📝 Generating private key..."
openssl genrsa -out "$SSL_DIR/wildbox.key" 4096

# Create certificate signing request configuration
echo "📄 Creating certificate configuration..."
cat > "$SSL_DIR/wildbox.conf" << EOF
[req]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
C=US
ST=California
L=San Francisco
O=Wildbox Security
OU=Development
CN=wildbox.local

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = wildbox.local
DNS.2 = *.wildbox.local
DNS.3 = api.wildbox.local
DNS.4 = dashboard.wildbox.local
DNS.5 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Generate certificate signing request
echo "📋 Generating certificate signing request..."
openssl req -new -key "$SSL_DIR/wildbox.key" -out "$SSL_DIR/wildbox.csr" -config "$SSL_DIR/wildbox.conf"

# Generate self-signed certificate
echo "🎫 Generating self-signed certificate..."
openssl x509 -req -in "$SSL_DIR/wildbox.csr" -signkey "$SSL_DIR/wildbox.key" -out "$SSL_DIR/wildbox.crt" -days 365 -extensions v3_req -extfile "$SSL_DIR/wildbox.conf"

# Set appropriate permissions
chmod 600 "$SSL_DIR/wildbox.key"
chmod 644 "$SSL_DIR/wildbox.crt"

# Clean up temporary files
rm "$SSL_DIR/wildbox.csr" "$SSL_DIR/wildbox.conf"

echo "✅ SSL certificates generated successfully!"
echo "📁 Certificate files:"
echo "   Private Key: $SSL_DIR/wildbox.key"
echo "   Certificate: $SSL_DIR/wildbox.crt"
echo ""
echo "⚠️  These are self-signed certificates for development only."
echo "   For production, use certificates from a trusted CA."
echo ""
echo "🔧 To trust the certificate on macOS:"
echo "   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain $SSL_DIR/wildbox.crt"
echo ""
echo "🔧 To add to /etc/hosts for local development:"
echo "   echo '127.0.0.1 wildbox.local api.wildbox.local dashboard.wildbox.local' | sudo tee -a /etc/hosts"
