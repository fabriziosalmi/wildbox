# Wildbox Security Gateway

🛡️ **Intelligent API Gateway for the Wildbox Security Suite**

The Wildbox Security Gateway is the unified entry point for all Wildbox services, providing advanced routing, authentication, authorization, and security features. Built on OpenResty (NGINX + LuaJIT) for maximum performance and flexibility.

## 🏗️ Architecture

The gateway acts as a reverse proxy and security enforcer, implementing:

- **Unified Routing**: Single entry point for all Wildbox services
- **TLS Termination**: Centralized SSL/TLS certificate management
- **Authentication & Authorization**: Token validation and user permission enforcement
- **Plan-based Feature Gating**: Dynamic access control based on subscription plans
- **Rate Limiting**: Per-plan API rate limiting
- **Caching**: Intelligent response caching to reduce backend load
- **Monitoring**: Comprehensive logging and metrics collection

## 🚀 Quick Start

### Prerequisites

- Docker and Docker Compose
- Make (optional, for convenience commands)

### 1. Start the Gateway

```bash
# Clone and navigate to the gateway directory
cd open-security-gateway

# Generate SSL certificates and start services
make start
```

### 2. Configure Local DNS

Add these entries to your `/etc/hosts` file:

```
127.0.0.1 wildbox.local
127.0.0.1 api.wildbox.local
127.0.0.1 dashboard.wildbox.local
```

### 3. Verify Installation

```bash
# Check health
curl -k https://wildbox.local/health

# View logs
make logs
```

## 🛣️ Routing Configuration

The gateway routes requests to backend services based on URL patterns:

| Path Pattern | Backend Service | Authentication | Plan Requirement |
|--------------|----------------|----------------|------------------|
| `/auth/*` | open-security-identity | ❌ | None |
| `/api/v1/identity/*` | open-security-identity | ✅ | Any |
| `/api/v1/data/*` | open-security-data | ✅ | Any |
| `/api/v1/cspm/*` | open-security-cspm | ✅ | Personal+ |
| `/api/v1/guardian/*` | open-security-guardian | ✅ | Any |
| `/api/v1/responder/*` | open-security-responder | ✅ | Business+ |
| `/api/v1/agents/*` | open-security-agents | ✅ | Enterprise |
| `/api/v1/sensor/*` | open-security-sensor | ✅ | Any |
| `/api/v1/automations/*` | open-security-automations | ✅ | Business+ |
| `/ws/*` | WebSocket connections | ✅ | Any |
| `/*` | open-security-dashboard | ✅ | Any |

## 🔐 Authentication

The gateway supports multiple authentication methods:

### Bearer Token (Recommended)
```bash
curl -H "Authorization: Bearer <token>" https://api.wildbox.local/api/v1/data/feeds
```

### API Key
```bash
curl -H "X-API-Key: <api-key>" https://api.wildbox.local/api/v1/data/feeds
```

### Query Parameter (Limited use)
```bash
curl "https://api.wildbox.local/api/v1/data/feeds?token=<token>"
```

## 📊 Subscription Plans & Features

The gateway enforces feature access based on subscription plans:

### Free Plan
- Dashboard access
- Basic monitoring
- Data feeds (limited)

### Personal Plan
- All Free features
- CSPM scanning
- Guardian threat detection
- Sensor data collection

### Business Plan
- All Personal features
- Incident response (Responder)
- Workflow automation
- Advanced analytics

### Enterprise Plan
- All Business features
- AI-powered security agents
- Custom integrations
- Priority support

## ⚡ Performance Features

### Intelligent Caching
- Authentication data cached for 5 minutes
- API responses cached based on user plan
- Static content cached with long TTLs

### Rate Limiting
- **Free**: 10 requests/second per team
- **Personal**: 50 requests/second per team
- **Business**: 200 requests/second per team
- **Enterprise**: 1000 requests/second per team

### Connection Pooling
- HTTP/1.1 keep-alive connections to backends
- Connection pooling for reduced latency
- Automatic failover and health checks

## 🔧 Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `WILDBOX_ENV` | `development` | Environment mode |
| `GATEWAY_LOG_LEVEL` | `info` | Log level (debug, info, warn, error) |

### Backend Service URLs

Backend services are automatically discovered via Docker networking:

- `open-security-identity:8000`
- `open-security-data:8001`
- `open-security-cspm:8002`
- `open-security-guardian:8003`
- `open-security-responder:8004`
- `open-security-agents:8005`
- `open-security-sensor:8006`
- `open-security-dashboard:3000`
- `open-security-automations:5678`

## 📋 Available Commands

```bash
# Basic operations
make start          # Start the gateway
make stop           # Stop the gateway
make restart        # Restart the gateway
make logs           # View logs

# Development
make dev-start      # Start in development mode
make shell          # Open shell in container
make config         # Test nginx configuration
make reload         # Reload configuration

# Maintenance
make certs          # Generate SSL certificates
make health         # Check service health
make clean          # Clean up resources
make backup         # Backup configuration
```

## 🐛 Debugging

### Enable Debug Logging

```bash
GATEWAY_LOG_LEVEL=debug make start
```

### Debug Headers

Set `gateway_debug=true` in nginx variables to enable debug headers:

- `X-Debug-User-ID`
- `X-Debug-Team-ID`
- `X-Debug-Plan`
- `X-Debug-Cache-Hit`

### View Real-time Logs

```bash
# All logs
make logs

# Access logs only
make metrics

# Error logs
docker-compose exec gateway tail -f /var/log/nginx/error.log
```

## 🔒 Security Features

### TLS Configuration
- TLS 1.2+ only
- Strong cipher suites
- HSTS headers
- OCSP stapling

### Security Headers
- `Strict-Transport-Security`
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `X-XSS-Protection`
- `Referrer-Policy`

### Input Validation
- Request size limits
- Header validation
- Path traversal protection

## 📈 Monitoring

### Health Check

```bash
curl -k https://wildbox.local/health
```

Response:
```json
{
  "status": "healthy",
  "service": "wildbox-gateway",
  "timestamp": "2024-01-15T10:30:00Z",
  "ssl": "enabled"
}
```

### Metrics

The gateway logs detailed metrics in structured format:

```
127.0.0.1 - - [15/Jan/2024:10:30:00 +0000] "GET /api/v1/data/feeds HTTP/1.1" 
200 1234 "-" "curl/7.68.0" "-" rt=0.045 uct="0.001" uht="0.002" urt="0.042" 
team_id="team_123" user_id="user_456" plan="business"
```

## 🚨 Troubleshooting

### Common Issues

1. **SSL Certificate Errors**
   ```bash
   # Regenerate certificates
   make certs
   
   # Trust certificate on macOS
   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ssl/wildbox.crt
   ```

2. **Backend Service Unreachable**
   ```bash
   # Check network connectivity
   docker network ls
   docker network inspect wildbox-net
   
   # Verify service status
   docker-compose ps
   ```

3. **Authentication Failures**
   ```bash
   # Check identity service logs
   docker-compose logs open-security-identity
   
   # Verify token format
   curl -H "Authorization: Bearer <token>" -v https://api.wildbox.local/api/v1/identity/me
   ```

### Log Analysis

```bash
# Filter authentication errors
docker-compose logs gateway | grep "authentication"

# Monitor rate limiting
docker-compose logs gateway | grep "rate_limit"

# Check backend errors
docker-compose logs gateway | grep "upstream"
```

## 🔄 Updates and Maintenance

### Update Gateway

```bash
make update
```

### Backup Configuration

```bash
make backup
```

### Rolling Updates (Production)

For zero-downtime updates in production:

1. Deploy new version alongside current
2. Update load balancer to point to new version
3. Wait for connections to drain
4. Remove old version

## 📚 Development

### Adding New Backend Services

1. Add upstream definition in `nginx/conf.d/wildbox_gateway.conf`
2. Add location block with appropriate authentication
3. Update documentation

### Modifying Authentication Logic

Edit `nginx/lua/auth_handler.lua` for authentication changes.

### Custom Rate Limiting

Modify rate limiting zones in `nginx/nginx.conf`.

## 🤝 Contributing

1. Fork the repository
2. Create feature branch
3. Make changes
4. Test thoroughly
5. Submit pull request

## 📄 License

Copyright © 2024 Wildbox Security. All rights reserved.
