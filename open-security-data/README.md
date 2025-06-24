# Open Security Data

A comprehensive security data lake platform that automatically collects, processes, and serves threat intelligence and security-related information from public sources.

## Overview

Open Security Data is designed to build and maintain a centralized repository of security information including:

- **Blacklists**: IP addresses, domains, URLs flagged as malicious
- **Threat Intelligence**: IOCs, malware signatures, attack patterns
- **Vulnerability Data**: CVE information, exploit databases
- **Certificate Intelligence**: SSL/TLS certificate transparency logs
- **DNS Intelligence**: Malicious domains, DNS resolution data
- **Network Intelligence**: Botnet C&C servers, scanning sources
- **File Intelligence**: Malware hashes, file reputation data

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Data Sources  │    │   Ingestion      │    │   Processing    │
│                 │    │                  │    │                 │
│ • Threat Feeds  │───▶│ • Collectors     │───▶│ • Validation    │
│ • Public APIs   │    │ • Schedulers     │    │ • Normalization │
│ • RSS Feeds     │    │ • Rate Limiters  │    │ • Enrichment    │
│ • Git Repos     │    │ • Transformers   │    │ • Deduplication │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                         │
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│      APIs       │    │     Storage      │    │   Data Lake     │
│                 │    │                  │    │                 │
│ • REST API      │◀───│ • PostgreSQL     │◀───│ • Raw Data      │
│ • GraphQL       │    │ • Redis Cache    │    │ • Processed     │
│ • WebSocket     │    │ • File Storage   │    │ • Enriched      │
│ • Export        │    │ • Time Series    │    │ • Analytics     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## Features

### Data Collection
- **Automated Collectors**: Scheduled collection from 50+ public threat intelligence sources
- **Rate Limiting**: Respectful API usage with configurable rate limits
- **Error Handling**: Robust error handling and retry mechanisms
- **Source Management**: Dynamic addition/removal of data sources

### Data Processing
- **Validation**: Schema validation and data quality checks
- **Normalization**: Standardized data formats across all sources
- **Enrichment**: Geographic, ASN, and contextual data enrichment
- **Deduplication**: Intelligent duplicate detection and merging

### Storage & Performance
- **Multi-tier Storage**: Hot, warm, and cold data storage strategies
- **Caching**: Redis-based caching for frequently accessed data
- **Indexing**: Optimized database indexes for fast queries
- **Partitioning**: Time-based and source-based data partitioning

### APIs & Access
- **REST API**: Full CRUD operations with OpenAPI documentation
- **GraphQL**: Flexible query interface for complex data relationships
- **Real-time**: WebSocket connections for live threat feeds
- **Export**: Bulk export in multiple formats (JSON, CSV, STIX)

### Monitoring & Analytics
- **Metrics**: Collection quality, API usage, and performance metrics
- **Dashboards**: Grafana dashboards for operational visibility
- **Alerting**: Real-time alerts for data quality issues
- **Reports**: Automated threat intelligence reports

## Quick Start

### Using Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/fabriziosalmi/wildbox.git
cd wildbox/open-security-data

# Start the platform
docker-compose up -d

# Initialize the database
docker-compose exec api python manage.py migrate
docker-compose exec api python manage.py create-admin

# Start data collection
docker-compose exec scheduler python -m app.scheduler.main
```

### Manual Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your configuration

# Initialize database
python manage.py migrate
python manage.py create-admin

# Start services
python -m app.api.main &          # API server
python -m app.scheduler.main &    # Data collection scheduler
python -m app.workers.main &      # Background workers
```

## Configuration

Key configuration options in `.env`:

```env
# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/securitydata

# Redis
REDIS_URL=redis://localhost:6379/0

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
API_WORKERS=4

# Data Collection
COLLECTION_INTERVAL=3600  # 1 hour
MAX_CONCURRENT_COLLECTORS=10
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60

# Storage
DATA_RETENTION_DAYS=365
ARCHIVE_AFTER_DAYS=90
```

## Data Sources

### Currently Supported Sources

| Source | Type | Data | Update Frequency |
|--------|------|------|------------------|
| Malware Domain List | Blacklist | Domains | Daily |
| Spamhaus | IP/Domain | Blocklists | Hourly |
| URLVoid | URL | Reputation | On-demand |
| VirusTotal | Hash/URL/IP | Intelligence | On-demand |
| AlienVault OTX | IOC | Threat Intel | Real-time |
| MISP | IOC | Threat Intel | Real-time |
| Certificate Transparency | Certificate | SSL/TLS Certs | Real-time |
| Shodan | IP/Port | Network Intel | Daily |
| GreyNoise | IP | Internet Scan Data | Real-time |
| AbuseIPDB | IP | Abuse Reports | Real-time |

### Adding New Sources

1. Create a collector in `app/collectors/sources/`
2. Define the data schema in `app/schemas/`
3. Add configuration in `config/sources.yaml`
4. Register in `app/collectors/registry.py`

## API Usage

### REST API Examples

```bash
# Get recent malicious IPs
curl "http://localhost:8001/api/v1/ips?status=malicious&limit=100"

# Search for domain intelligence
curl "http://localhost:8001/api/v1/domains/example.com"

# Get threat intelligence by hash
curl "http://localhost:8001/api/v1/hashes/d41d8cd98f00b204e9800998ecf8427e"

# Real-time threat feed
curl "http://localhost:8001/api/v1/feeds/realtime" \
  -H "Accept: application/x-ndjson"
```

### GraphQL Examples

```graphql
# Complex threat intelligence query
query ThreatIntelligence($domain: String!) {
  domain(name: $domain) {
    name
    reputation
    firstSeen
    lastSeen
    associatedIps {
      address
      asn
      country
    }
    certificates {
      issuer
      subject
      validFrom
      validTo
    }
    threatFeeds {
      source
      category
      confidence
      description
    }
  }
}
```

## Development

### Project Structure

```
open-security-data/
├── app/                     # Main application code
│   ├── api/                # REST API and GraphQL endpoints
│   ├── collectors/         # Data collection modules
│   ├── processors/         # Data processing pipelines
│   ├── storage/            # Database models and storage
│   ├── scheduler/          # Job scheduling and management
│   ├── workers/            # Background task workers
│   └── utils/              # Shared utilities
├── config/                 # Configuration files
├── docker/                 # Docker configuration
├── docs/                   # Documentation
├── scripts/                # Utility scripts
├── tests/                  # Test suite
└── requirements/           # Python dependencies
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run specific test category
pytest tests/collectors/
pytest tests/api/
```

### Code Quality

```bash
# Format code
black app/ tests/

# Lint code
flake8 app/ tests/

# Type checking
mypy app/

# Security scanning
bandit -r app/
```

## Deployment

### Production Deployment

See [docs/deployment.md](docs/deployment.md) for detailed production deployment instructions including:

- Kubernetes manifests
- Database optimization
- Monitoring setup
- Backup strategies
- Security hardening

### Scaling

The platform is designed to scale horizontally:

- **API**: Multiple API server instances behind a load balancer
- **Collectors**: Distributed collection workers
- **Database**: Read replicas and sharding support
- **Cache**: Redis clustering
- **Storage**: Object storage for large datasets

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run quality checks
6. Submit a pull request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/your-org/open-security-data/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/open-security-data/discussions)
- **Security**: security@your-org.com

## Acknowledgments

This project builds upon the excellent work of the threat intelligence community and incorporates data from numerous public sources. We thank all the organizations and individuals who make their threat intelligence available to the community.
