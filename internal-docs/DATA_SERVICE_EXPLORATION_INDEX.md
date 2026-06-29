# Data Service - Comprehensive Exploration Index

## Documents Overview

This index provides navigation to all documentation related to the Open Security Data Service codebase exploration.

### Generated Documentation Files

1. **DATA_SERVICE_API_DOCUMENTATION.md** (28 KB)
   - Complete API reference with detailed endpoint descriptions
   - Data models and database schema documentation
   - Authentication and security configuration
   - Query capabilities and filtering options
   - Pagination and sorting mechanisms
   - Key functionality descriptions with examples
   - Error handling and status codes
   - Performance considerations

2. **DATA_SERVICE_QUICK_REFERENCE.md** (7.7 KB)
   - Quick lookup tables for endpoints
   - Summary of response patterns
   - Field specifications and enumerations
   - Event type definitions
   - Rate limiting information
   - Pagination guide with examples
   - Common query examples
   - Configuration essentials

---

## Project Structure

```
open-security-data/
├── app/
│   ├── api/
│   │   └── main.py               # FastAPI application and endpoints
│   ├── collectors/
│   │   ├── __init__.py
│   │   └── sources.py            # Data source collector implementations
│   ├── models.py                 # SQLAlchemy ORM models
│   ├── schemas/
│   │   └── api.py                # Pydantic schemas and validation
│   ├── config.py                 # Configuration management
│   ├── utils/
│   │   ├── database.py           # Database session management
│   │   ├── rate_limiter.py       # Rate limiting utilities
│   │   ├── validators.py         # Input validation functions
│   │   └── normalizers.py        # Data normalization functions
│   └── scheduler/
│       └── main.py               # Collection scheduling
├── README.md                     # Service overview
├── QUICKSTART.md                 # Getting started guide
└── requirements.txt              # Python dependencies
```

---

## Key Files Analyzed

### Application Entry Point
- **File**: `/Users/fab/GitHub/wildbox/open-security-data/app/api/main.py`
- **Type**: FastAPI Application
- **Lines**: 806
- **Purpose**: Defines all API endpoints, request/response handling
- **Key Functions**:
  - `health_check()` - Health status endpoint
  - `get_statistics()` - System statistics aggregation
  - `search_indicators()` - Advanced indicator search with filtering
  - `get_indicator()` - Detailed indicator retrieval
  - `bulk_lookup()` - Batch indicator lookups
  - `get_ip_intelligence()` - IP enrichment endpoint
  - `get_domain_intelligence()` - Domain enrichment endpoint
  - `get_hash_intelligence()` - Hash enrichment endpoint
  - `list_sources()` - Data source listing
  - `realtime_feed()` - Streaming threat feed
  - `ingest_telemetry_batch()` - Event batch ingestion
  - `get_telemetry_events()` - Event query endpoint
  - `get_sensors()` - Sensor listing
  - `get_sensor()` - Specific sensor details
  - `get_telemetry_stats()` - Telemetry statistics

### Data Models
- **File**: `/Users/fab/GitHub/wildbox/open-security-data/app/models.py`
- **Type**: SQLAlchemy ORM Models
- **Tables**: 9 main entities
- **Key Models**:
  - `Source` - Data source definitions (feed, API, file configurations)
  - `Indicator` - Security indicators (IOCs) with threat classification
  - `IPAddress` - IP-specific enrichment data (ASN, geolocation)
  - `Domain` - Domain-specific enrichment data (WHOIS, DNS)
  - `FileHash` - Hash-specific enrichment data (malware family, signatures)
  - `Enrichment` - Generic enrichment data storage
  - `CollectionRun` - Collection job tracking
  - `TelemetryEvent` - Sensor telemetry event storage
  - `SensorMetadata` - Sensor registration and status tracking

### Schemas & Validation
- **File**: `/Users/fab/GitHub/wildbox/open-security-data/app/schemas/api.py`
- **Type**: Pydantic Models (Request/Response)
- **Classes**: 25+ schema definitions
- **Purpose**: Input validation, response serialization, OpenAPI documentation

### Configuration Management
- **File**: `/Users/fab/GitHub/wildbox/open-security-data/app/config.py`
- **Type**: Configuration Class (Dataclasses)
- **Config Sections**: 8 sections
- **Environment Variables**: 50+
- **Settings**: Database, Redis, API, Collection, Storage, Security, Logging, Monitoring

### Utilities

#### Database Utilities
- **File**: `/Users/fab/GitHub/wildbox/open-security-data/app/utils/database.py`
- **Purpose**: SQLAlchemy engine setup, session management, table creation
- **Key Functions**: `get_db_session()`, `create_tables()`, `drop_tables()`

#### Rate Limiting
- **File**: `/Users/fab/GitHub/wildbox/open-security-data/app/utils/rate_limiter.py`
- **Purpose**: Async rate limiting with sliding window
- **Classes**: `RateLimiter`, `GlobalRateLimiter`
- **Mechanism**: Sliding window with configurable max requests and time window

#### Validators
- **File**: `/Users/fab/GitHub/wildbox/open-security-data/app/utils/validators.py`
- **Purpose**: Security indicator validation (IP, domain, hash, email, etc.)
- **Functions**: 15+ type-specific validators
- **Coverage**: IP addresses, domains, URLs, hashes, emails, ASNs, CVEs
- **Features**: Pattern matching, range validation, format verification

#### Normalizers
- **File**: `/Users/fab/GitHub/wildbox/open-security-data/app/utils/normalizers.py`
- **Purpose**: Standardize indicator formats for consistency
- **Functions**: Type-specific normalization, timestamp parsing, fingerprint generation
- **Features**: Deduplication support, indicator merging, metadata handling

---

## API Endpoint Summary

### Total Endpoints: 16

#### By Category

**Health & Statistics (3)**
- GET /health
- GET /api/v1/stats
- GET /api/v1/dashboard/threat-intel

**Indicator Search & Lookup (3)**
- GET /api/v1/indicators/search
- GET /api/v1/indicators/{indicator_id}
- POST /api/v1/indicators/lookup

**Type-Specific Intelligence (3)**
- GET /api/v1/ips/{ip_address}
- GET /api/v1/domains/{domain}
- GET /api/v1/hashes/{file_hash}

**Sources & Feeds (2)**
- GET /api/v1/sources
- GET /api/v1/feeds/realtime

**Telemetry Ingestion & Query (5)**
- POST /api/v1/ingest
- GET /api/v1/telemetry/events
- GET /api/v1/telemetry/stats
- GET /api/v1/sensors
- GET /api/v1/sensors/{sensor_id}

---

## Data Models Summary

### Indicator Types (8)
- ip_address
- domain
- url
- file_hash
- email
- certificate
- asn
- vulnerability

### Threat Types (10)
- malware
- phishing
- spam
- botnet
- exploit
- vulnerability
- certificate
- dns
- network_scan
- suspicious

### Confidence Levels (4)
- low
- medium
- high
- verified

### Severity Scale
- 1-10 rating system
- Inclusive range filtering supported

### Event Types (7)
- process_event
- network_connection
- file_change
- user_event
- system_inventory
- authentication
- security_event

---

## Authentication & Security

### Current Configuration
- **Type**: Optional API Key
- **Header**: X-API-Key
- **Default Status**: Disabled (API_KEY_REQUIRED=false)
- **Production**: Should be enabled

### Rate Limiting
- **Default**: 100 requests per 60 seconds
- **Configurable**: Yes (RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW)
- **Batch Size Limit**: 1000 items
- **Query Size Limit**: 10,000 characters
- **Status When Limited**: 429 Too Many Requests

### Input Validation
- Type-specific validators for each indicator type
- Pattern matching for IP addresses, domains, URLs
- Hash format and length validation
- CVE format validation

### Data Normalization
- Automatic case normalization (domains, hashes, emails)
- URL normalization (scheme, port defaults, fragment removal)
- IP address standardization with version detection
- Timestamp parsing and UTC conversion

---

## Query Capabilities

### Search Filters (Indicators)
1. **Text Search**: `q` parameter (full-text across value, normalized_value, description)
2. **Type Filter**: `indicator_type` (single type selection)
3. **Threat Types**: `threat_types` (multiple threat types, array support)
4. **Confidence**: `confidence` (single level: low, medium, high, verified)
5. **Severity Range**: `min_severity`, `max_severity` (1-10 scale)
6. **Source Filter**: `source_id` (UUID exact match)
7. **Time Range**: `since` (ISO 8601 datetime, >= comparison)
8. **Active Status**: `active_only` (boolean, default: true)

### Pagination
- **Limit**: 1-10,000 (default: 100)
- **Offset**: 0+ (cursor-free pagination)
- **Response Fields**: total, limit, offset, query_time
- **Calculation**: `ceil(total / limit)` = total pages

### Sorting
- Indicators: By `last_seen DESC` (most recent first)
- Telemetry: By `timestamp DESC`
- Sensors: By `last_seen DESC`

### Advanced Features
- **Bulk Lookup**: POST /api/v1/indicators/lookup (max 1000 items)
- **Streaming**: GET /api/v1/feeds/realtime (NDJSON format, 1000 limit)
- **Real-Time Feed**: Configurable lookback window (1-1440 minutes)

---

## Key Functionality Breakdown

### 1. Data Aggregation
- **Sources Supported**: 50+ public threat intelligence sources
- **Collection Methods**: 
  - HTTP feeds
  - Public APIs
  - RSS feeds
  - Git repositories
  - File uploads
- **Scheduling**: Configurable intervals (default: 3600 seconds)
- **Concurrency**: Configurable max concurrent collectors (default: 10)
- **Rate Limiting**: Per-source and global rate limits
- **Retry Logic**: Configurable retry attempts (default: 3)

### 2. Data Processing & Normalization
- **Validation**: Input validation using defined schemas
- **Normalization**: Type-specific format standardization
- **Deduplication**: Fingerprint-based duplicate detection
- **Enrichment**: Geographic, ASN, WHOIS lookups
- **Merging**: Intelligent indicator record merging

### 3. Data Analysis & Enrichment
- **IP Analysis**: ASN, geolocation, organization, coordinates
- **Domain Analysis**: TLD, registrar, creation/expiration dates, DNS records
- **Hash Analysis**: File metadata, malware family, AV signatures, detection ratios
- **Confidence Scoring**: 4-level confidence system
- **Severity Ratings**: 1-10 scale with range filtering

### 4. Real-Time Reporting
- **Dashboard Metrics**: Feeds, new indicators, trend analysis
- **Real-Time Stream**: NDJSON format with keep-alive support
- **Configurable Lookback**: 1-1440 minute windows
- **Filtering**: By type, threat category, severity

### 5. Telemetry Integration
- **Event Types**: 7 event type categories
- **Batch Processing**: Configurable batch size (default: 1000)
- **Sensor Registration**: Automatic on first event
- **Activity Tracking**: First seen, last seen, total events
- **Statistics**: Event counts by type, active sensor count

### 6. Data Management
- **Lifecycle**: first_seen, last_seen, expires_at tracking
- **Status Flags**: active, false_positive, whitelisted
- **Retention**: Configurable retention period (default: 365 days)
- **Archival**: Automatic archiving after period (default: 90 days)
- **Backup**: Optional with configurable intervals

---

## Database Schema

### Table Statistics
- **Total Tables**: 9
- **Total Indexes**: 25+
- **Key Constraint**: (source_id, indicator_type, normalized_value) unique on Indicator table
- **Type Hierarchy**: Indicator with 1:1 relationships to IPAddress, Domain, FileHash

### Storage Architecture
- **Primary Database**: PostgreSQL
- **Cache Layer**: Redis (optional)
- **File Storage**: Configurable path for attachments
- **Type System**: UUID primary keys, JSON for flexible metadata

### Performance Features
- **Indexed Fields**: Type-value combo, source, timestamps, status flags
- **Partitioning**: Support for time-based and source-based partitioning
- **Connection Pooling**: SQLAlchemy with configurable pool size (default: 20)
- **Compound Indexes**: Multi-field indexes for common query patterns

---

## Error Handling

### HTTP Status Codes
- `200 OK`: Successful request
- `400 Bad Request`: Invalid parameters, validation errors, batch size exceeded
- `404 Not Found`: Resource not found
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server-side error

### Error Response Format
```json
{
  "detail": "Error message description",
  "status_code": 400
}
```

### Common Error Scenarios
1. **Batch Size Exceeded**: Detail: "Too many indicators. Maximum allowed: {limit}"
2. **Not Found**: Detail: "Indicator not found" / "Sensor {id} not found"
3. **Invalid Type**: Detail: "Invalid indicator type"
4. **Rate Limited**: Status: 429 with retry-after headers

---

## Configuration Reference

### Database
```
DATABASE_URL: PostgreSQL connection string
DB_POOL_SIZE: 20 (connection pool size)
DB_MAX_OVERFLOW: 10 (additional connections beyond pool)
DB_POOL_TIMEOUT: 30 (timeout for acquiring connection)
DB_ECHO: false (SQL logging)
```

### API Server
```
API_HOST: 0.0.0.0
API_PORT: 8002
API_WORKERS: 4
API_TIMEOUT: 30
CORS_ENABLED: true
CORS_ORIGINS: ["*"] (or specific origins)
```

### Security
```
API_KEY_REQUIRED: false (set to true in production)
API_KEY_HEADER: "X-API-Key"
MAX_BATCH_SIZE: 1000
MAX_QUERY_SIZE: 10000
RATE_LIMIT_ENABLED: true
RATE_LIMIT_REQUESTS: 100
RATE_LIMIT_WINDOW: 60
```

### Collection
```
COLLECTION_ENABLED: true
COLLECTION_INTERVAL: 3600 (seconds)
MAX_CONCURRENT_COLLECTORS: 10
COLLECTION_TIMEOUT: 300 (seconds)
COLLECTION_RETRY_ATTEMPTS: 3
SKIP_DUPLICATES: true
VALIDATE_COLLECTION_DATA: true
```

### Storage
```
DATA_RETENTION_DAYS: 365
ARCHIVE_AFTER_DAYS: 90
BACKUP_ENABLED: false
BACKUP_INTERVAL: 86400 (24 hours)
BACKUP_RETENTION: 30 (days)
FILE_STORAGE_PATH: ./data/files
MAX_FILE_SIZE: 104857600 (100MB)
```

### Logging
```
LOG_LEVEL: INFO
LOG_FILE_ENABLED: true
LOG_FILE_PATH: ./logs/app.log
LOG_JSON_FORMAT: false
SENTRY_ENABLED: false
```

---

## Integration Points

### Data Sources
Supports collection from:
- Malware Domain List
- AbuseIPDB
- Spamhaus
- URLVoid
- VirusTotal
- AlienVault OTX
- MISP
- Certificate Transparency
- Shodan
- GreyNoise

### External Systems
- PostgreSQL database
- Redis cache
- HTTP/REST APIs
- NDJSON streaming clients
- Sensor telemetry systems

---

## Performance Metrics

### Scaling Characteristics
- **Horizontal**: Multiple API instances behind load balancer
- **Distributed Collection**: Concurrent collectors with rate limiting
- **Database**: Read replicas supported
- **Cache**: Redis clustering available

### Response Times (Expected)
- Search with pagination: <100ms (cached)
- Bulk lookup (100 items): <500ms
- Real-time stream: Streaming with minimal latency
- Telemetry ingest: <200ms per batch

### Capacity
- **API Throughput**: 100 requests/sec with default rate limits
- **Batch Size**: Up to 1000 items per operation
- **Query Result Size**: Limited by available memory
- **Stream Connections**: Limited by worker processes

---

## Testing & Validation

### Validators Provided
- IP address validation (IPv4 and IPv6)
- Domain name validation
- URL validation
- File hash validation (MD5, SHA1, SHA256, SHA512)
- Email address validation
- ASN validation
- CVE identifier validation

### Example Validations
- IPs: `ipaddress.ip_address()` with format check
- Domains: Regex pattern with length limits
- Hashes: Hex string validation with length matching
- Confidence: Enum validation (low, medium, high, verified)
- Severity: Range validation (1-10)

---

## Monitoring & Observability

### Endpoints for Monitoring
- `/health` - Service health (for Kubernetes probes)
- `/api/v1/stats` - System statistics
- `/api/v1/dashboard/threat-intel` - Dashboard metrics
- `/api/v1/telemetry/stats` - Telemetry statistics

### Metrics Available
- Total and active indicators by type
- Data source counts and status
- Collection frequency and success rates
- Telemetry event counts and types
- Sensor registration and activity

### Logging Configuration
- File-based logging with rotation (10MB, 5 backups default)
- Optional JSON structured logging
- Optional Sentry integration for error tracking
- Configurable log levels

---

## Security Considerations

### Current Status
- API key authentication: Optional (disabled by default)
- CORS: Configurable with origin whitelist
- Rate limiting: Enabled by default
- Input validation: Comprehensive per type
- Database: No ORM injection vulnerabilities detected

### Recommendations for Production
1. Enable API_KEY_REQUIRED=true
2. Implement strong API key rotation
3. Use HTTPS for all connections
4. Restrict CORS_ORIGINS to specific domains
5. Enable database encryption at rest
6. Monitor rate limit violations
7. Enable Sentry for error tracking
8. Use environment variables for secrets

---

## Source Code Statistics

### Python Files Analyzed
1. `/Users/fab/GitHub/wildbox/open-security-data/app/api/main.py` - 806 lines
2. `/Users/fab/GitHub/wildbox/open-security-data/app/models.py` - 408 lines
3. `/Users/fab/GitHub/wildbox/open-security-data/app/schemas/api.py` - 297 lines
4. `/Users/fab/GitHub/wildbox/open-security-data/app/config.py` - 194 lines
5. `/Users/fab/GitHub/wildbox/open-security-data/app/utils/normalizers.py` - 339 lines
6. `/Users/fab/GitHub/wildbox/open-security-data/app/utils/validators.py` - 282 lines
7. `/Users/fab/GitHub/wildbox/open-security-data/app/utils/rate_limiter.py` - 103 lines
8. `/Users/fab/GitHub/wildbox/open-security-data/app/utils/database.py` - 50 lines
9. `/Users/fab/GitHub/wildbox/open-security-data/app/collectors/sources.py` - 100+ lines

**Total**: ~2,500+ lines of core application code

---

## Quick Navigation

### For API Integration
- Start with: **DATA_SERVICE_QUICK_REFERENCE.md**
- Common queries: Section "Common Query Examples"
- Endpoint list: Section "API Endpoints Summary"

### For Detailed Implementation
- Full documentation: **DATA_SERVICE_API_DOCUMENTATION.md**
- Endpoints by category: Section "API Endpoints by Category"
- Data models: Section "Data Models & Schemas"
- Error handling: Section "Error Handling"

### For Operations & Configuration
- Configuration: **DATA_SERVICE_API_DOCUMENTATION.md** Section "Configuration Summary"
- Database: Section "Data Models & Schemas" - Database Tables
- Monitoring: This document Section "Monitoring & Observability"
- Security: This document Section "Security Considerations"

### For Development
- Code structure: This document Section "Project Structure"
- Utilities: Section "Key Files Analyzed"
- Validation: **DATA_SERVICE_API_DOCUMENTATION.md** - Section "Data Validation"
- Rate limiting: Section "Rate Limiting Defaults"

---

## Conclusion

The Open Security Data Service is a comprehensive threat intelligence platform with:
- 16 well-structured REST API endpoints
- Support for 8 indicator types and 10 threat classifications
- Advanced querying with full-text search and filtering
- Real-time streaming capabilities
- Telemetry and sensor event ingestion
- Configurable data aggregation from 50+ sources
- Production-ready database design with proper indexing

All major components have been documented with usage examples, configuration options, and integration patterns.

