# Open Security Identity

The central identity, authentication, authorization, and billing service for the Wildbox Security Suite.

## Overview

Open Security Identity is the critical microservice that manages:

- **User Registration & Authentication**: JWT-based authentication for users
- **Team Management**: Organization and team membership handling  
- **API Key Management**: Service-to-service authentication via API keys
- **Subscription & Billing**: Stripe integration for plan management
- **Authorization**: Centralized permissions and rate limiting for all Wildbox services

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Frontend      │    │   API Gateway    │    │  Other Services │
│                 │    │                  │    │                 │
│ • Dashboard     │◀──▶│ • Routing        │◀──▶│ • Agents        │
│ • User Portal   │    │ • Rate Limiting  │    │ • Responder     │
│ • Billing       │    │ • Auth Check     │    │ • Scanner       │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                        │                       │
         └────────────────────────┼───────────────────────┘
                                  │
                     ┌──────────────────┐
                     │ Identity Service │
                     │                  │
                     │ • JWT Auth       │
                     │ • API Keys       │
                     │ • Teams          │
                     │ • Billing        │
                     │ • Permissions    │
                     └──────────────────┘
                              │
                     ┌──────────────────┐
                     │    Database      │
                     │                  │
                     │ • PostgreSQL     │
                     │ • Users/Teams    │
                     │ • Subscriptions  │
                     │ • API Keys       │
                     └──────────────────┘
```

## Features

### 🔐 Authentication & Authorization
- JWT token-based user authentication
- API key authentication for service-to-service communication
- Role-based access control (Owner, Admin, Member)
- Secure password hashing with bcrypt

### 👥 Team Management
- Multi-tenant team/organization support
- Team ownership and membership management
- Per-team subscription and billing

### 🔑 API Key Management
- Secure API key generation and storage
- Prefix-based key identification (wsk_xxxx)
- Key expiration and usage tracking
- Team-scoped key management

### 💳 Billing Integration
- Stripe Checkout for subscription management
- Customer Portal for self-service billing
- Webhook handling for real-time updates
- Multiple subscription tiers (Free, Pro, Business)

### 🛡️ Security Features
- Password validation and hashing
- API key hashing and secure comparison
- Webhook signature verification
- Rate limiting by subscription tier

## Quick Start

### Using Docker (Recommended)

```bash
# Clone and navigate to directory
cd open-security-identity

# Copy environment configuration
cp .env.example .env

# Edit .env with your configuration
nano .env

# Start services
make dev

# Run database migrations
make db-migrate
```

### Manual Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export DATABASE_URL="postgresql+asyncpg://user:pass@localhost/identity"
export JWT_SECRET_KEY="your-secret-key"
export STRIPE_SECRET_KEY="sk_test_..."

# Run migrations
alembic upgrade head

# Start the application
uvicorn app.main:app --reload
```

## Configuration

Key environment variables:

```env
# Database
DATABASE_URL=postgresql+asyncpg://postgres:password@localhost:5432/identity_db

# JWT Configuration  
JWT_SECRET_KEY=your-super-secret-jwt-key-change-in-production
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30

# Stripe Configuration
STRIPE_SECRET_KEY=sk_test_your_stripe_secret_key
STRIPE_PUBLISHABLE_KEY=pk_test_your_stripe_publishable_key  
STRIPE_WEBHOOK_SECRET=whsec_your_webhook_secret

# Application
DEBUG=false
FRONTEND_URL=http://localhost:3000
```

## API Endpoints

### Authentication
- `POST /api/v1/auth/register` - Register new user
- `POST /api/v1/auth/login` - User login
- `GET /api/v1/auth/me` - Get current user info

### API Keys
- `POST /api/v1/teams/{team_id}/api-keys` - Create API key
- `GET /api/v1/teams/{team_id}/api-keys` - List API keys
- `DELETE /api/v1/teams/{team_id}/api-keys/{prefix}` - Revoke API key

### Billing
- `POST /api/v1/billing/create-checkout-session` - Create Stripe checkout
- `POST /api/v1/billing/create-portal-session` - Create customer portal

### Internal (Service-to-Service)
- `POST /internal/authorize` - Authorize API key and get permissions

### Webhooks
- `POST /webhooks/stripe` - Stripe webhook handler

## Subscription Plans

### Free Plan
- Basic tool access
- 100 API calls/hour
- 10 tool executions/hour
- Community support

### Pro Plan ($29/month)
- Advanced tools
- Premium threat feeds
- 1,000 API calls/hour
- 100 tool executions/hour
- Email support

### Business Plan ($99/month)
- Enterprise tools
- Premium + enterprise feeds
- Advanced CSPM scanning
- 10,000 API calls/hour
- 1,000 tool executions/hour
- Priority support

## Development

### Running Tests

```bash
# Run all tests
make test

# With coverage
pytest --cov=app --cov-report=html
```

### Code Quality

```bash
# Format code
make format

# Lint code  
make lint

# Type checking
make type-check

# Run all quality checks
make quality
```

### Database Migrations

```bash
# Create new migration
alembic revision --autogenerate -m "Description"

# Apply migrations
alembic upgrade head

# Rollback migration
alembic downgrade -1
```

## Security Considerations

### Production Deployment

1. **Change all default secrets** in environment variables
2. **Use HTTPS** for all communication
3. **Configure proper CORS** settings
4. **Set up database encryption** at rest and in transit
5. **Enable audit logging** for all authentication events
6. **Use strong JWT secrets** (minimum 256 bits)
7. **Implement rate limiting** at the reverse proxy level
8. **Regular security updates** for all dependencies

### API Key Security

- API keys are hashed using SHA-256 before storage
- Full keys are only shown once during creation
- Keys support expiration dates for enhanced security
- Usage tracking for audit purposes

### Database Security

- All passwords hashed with bcrypt
- UUID primary keys prevent enumeration
- Proper foreign key constraints
- Audit timestamps on all records

## Monitoring

The service exposes several endpoints for monitoring:

- `GET /` - Service information
- `GET /health` - Health check
- `GET /docs` - API documentation

Key metrics to monitor:
- Authentication success/failure rates
- API key usage patterns
- Subscription status changes
- Database connection health
- Response times and error rates

## Integration

### With API Gateway

The API Gateway calls `/internal/authorize` for each request:

```python
# Request to identity service
{
  "headers": {"Authorization": "Bearer wsk_xxx.yyy"}
}

# Response from identity service
{
  "is_authenticated": true,
  "user_id": "uuid",
  "team_id": "uuid", 
  "role": "owner",
  "plan": "pro",
  "permissions": ["tool:advanced", "feed:premium"],
  "rate_limits": {"default": "1000/hour"}
}
```

### With Frontend

The frontend receives JWT tokens from login/register endpoints and includes them in subsequent requests:

```javascript
// Login request
const response = await fetch('/api/v1/auth/login', {
  method: 'POST',
  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
  body: 'username=user@example.com&password=secret'
});

const {access_token} = await response.json();

// Subsequent requests
const user = await fetch('/api/v1/auth/me', {
  headers: {'Authorization': `Bearer ${access_token}`}
});
```

## Support

- **Documentation**: `/docs` endpoint
- **Issues**: GitHub Issues
- **Security Issues**: security@wildbox.com

## License

MIT License - see LICENSE file for details.

---

Part of the [Wildbox Security Suite](https://github.com/fabriziosalmi/wildbox)
