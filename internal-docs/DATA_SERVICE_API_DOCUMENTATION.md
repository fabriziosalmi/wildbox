# Open Security Data Service - Complete API Documentation

## Table of Contents
1. [Overview](#overview)
2. [Authentication & Security](#authentication--security)
3. [API Endpoints by Category](#api-endpoints-by-category)
4. [Data Models & Schemas](#data-models--schemas)
5. [Query Capabilities](#query-capabilities)
6. [Pagination & Sorting](#pagination--sorting)
7. [Key Functionality](#key-functionality)

---

## Overview

The Open Security Data Service is a FastAPI-based security data lake providing threat intelligence, IOCs, and security-related data aggregation, analysis, and reporting. The service handles:

- **Threat Intelligence Collection**: Automated collection from 50+ public sources
- **Data Aggregation**: Centralized repository for security indicators
- **Analysis & Enrichment**: Geographic, ASN, and contextual data enrichment
- **Real-time Feeds**: Live threat intelligence streaming
- **Telemetry Ingestion**: Security sensor event processing

**Service Details:**
- Framework: FastAPI 1.0.0
- Database: PostgreSQL with SQLAlchemy ORM
- Caching: Redis support
- API Port: 8002 (default)
- Base Path: `/api/v1`

---

## Authentication & Security

### Current Implementation
- **API Key Authentication**: Optional (controlled by `API_KEY_REQUIRED` config)
- **Header**: `X-API-Key` (configurable via `API_KEY_HEADER`)
- **CORS**: Configurable with origins whitelist
- **Rate Limiting**: 
  - Per-endpoint: 100 requests/60 seconds (configurable)
  - Batch operations: Limited by `max_batch_size` (default: 1000)
  - Query size limit: 10000 characters (default)

### Security Configuration
```
API_KEY_REQUIRED=false                    # Enable API key requirement
API_KEY_HEADER=X-API-Key                 # Header name for API key
RATE_LIMIT_ENABLED=true                  # Enable rate limiting
RATE_LIMIT_REQUESTS=100                  # Requests per window
RATE_LIMIT_WINDOW=60                     # Time window in seconds
MAX_BATCH_SIZE=1000                      # Max items in batch operations
MAX_QUERY_SIZE=10000                     # Max query size in characters
```

### Data Validation
- Input validation for all indicator types (IP, domain, hash, etc.)
- Normalized value storage for deduplication
- JSON schema validation for complex objects

---

## API Endpoints by Category

### Health & Monitoring

#### Health Check
```
GET /health
Tags: Health
Response: HealthResponse
```
Returns service health status and version information.

**Response Example:**
```json
{
  "status": "healthy",
  "timestamp": "2025-11-07T20:30:00Z",
  "version": "1.0.0"
}
```

---

### Statistics & Dashboard

#### System Statistics
```
GET /api/v1/stats
Tags: Statistics
Response: SystemStats
```
Retrieves overall system statistics including indicator counts by type, source information, and collection metrics.

**Response Fields:**
- `total_indicators` (int): Total active indicators
- `indicator_types` (object): Count breakdown by indicator type
- `total_sources` (int): Total data sources configured
- `active_sources` (int): Currently enabled sources
- `recent_collections` (int): Collections in last 24 hours
- `timestamp` (datetime): Generation timestamp

---

#### Threat Intelligence Dashboard Metrics
```
GET /api/v1/dashboard/threat-intel
Tags: Dashboard
Response: Object
```
Dashboard-optimized threat intelligence metrics with trends.

**Response Fields:**
- `total_feeds` (int): Total configured feeds
- `active_feeds` (int): Active feeds
- `last_updated` (datetime): Last collection timestamp
- `new_indicators` (int): New indicators in last 24 hours
- `trends_change` (float): Percentage change vs previous 24 hours

---

### Indicators - Search & Query

#### Search Indicators
```
GET /api/v1/indicators/search
Tags: Indicators
Response: IndicatorSearchResponse
```

**Query Parameters:**
| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| q | string | Search query (full-text) | None |
| indicator_type | string | Filter by type (ip_address, domain, file_hash, etc.) | None |
| threat_types | string[] | Filter by threat types | None |
| confidence | string | Filter by confidence (low, medium, high, verified) | None |
| min_severity | int | Minimum severity (1-10) | None |
| max_severity | int | Maximum severity (1-10) | None |
| source_id | string | Filter by source ID | None |
| since | datetime | Show indicators since date | None |
| active_only | bool | Return only active indicators | true |
| limit | int | Results per page (1-10000) | 100 |
| offset | int | Pagination offset (0+) | 0 |

**Response:**
```json
{
  "indicators": [
    {
      "id": "uuid",
      "indicator_type": "ip_address",
      "value": "192.0.2.1",
      "normalized_value": "192.0.2.1",
      "threat_types": ["malware", "botnet"],
      "confidence": "high",
      "severity": 8,
      "description": "Known malicious IP",
      "tags": ["malware", "botnet"],
      "first_seen": "2025-11-06T10:00:00Z",
      "last_seen": "2025-11-07T20:00:00Z",
      "expires_at": "2025-12-07T20:00:00Z",
      "active": true,
      "source_id": "uuid",
      "created_at": "2025-11-06T10:00:00Z",
      "updated_at": "2025-11-07T20:00:00Z"
    }
  ],
  "total": 150,
  "limit": 100,
  "offset": 0,
  "query_time": "2025-11-07T20:30:00Z"
}
```

---

#### Get Indicator Details
```
GET /api/v1/indicators/{indicator_id}
Tags: Indicators
Response: IndicatorDetail
Path Parameters:
  - indicator_id (string, required): UUID of indicator
```

Returns detailed indicator information with enrichment data based on type (IP geolocation, domain WHOIS, hash analysis, etc.).

**Response Includes:**
- Base indicator fields (from IndicatorResponse)
- `enrichment` (object): Type-specific enrichment data
- `raw_data` (object): Original source data

---

#### Bulk Indicator Lookup
```
POST /api/v1/indicators/lookup
Tags: Indicators
Request: BulkLookupRequest
Response: BulkLookupResponse
```

Perform batch lookups of multiple indicators in a single request.

**Request Body:**
```json
{
  "indicators": [
    {
      "indicator_type": "ip_address",
      "value": "192.0.2.1"
    },
    {
      "indicator_type": "domain",
      "value": "malicious.com"
    }
  ]
}
```

**Constraints:**
- Maximum batch size: 1000 items (configurable)
- Returns matches for each queried indicator

**Response:**
```json
{
  "results": [
    {
      "indicator_type": "ip_address",
      "value": "192.0.2.1",
      "found": true,
      "matches": [/* indicator objects */]
    }
  ],
  "total_queried": 2,
  "total_found": 1,
  "query_time": "2025-11-07T20:30:00Z"
}
```

---

### IP Intelligence

#### Get IP Address Intelligence
```
GET /api/v1/ips/{ip_address}
Tags: IP Intelligence
Response: IPIntelligence
Path Parameters:
  - ip_address (string, required): IP address (IPv4 or IPv6)
```

**Enrichment Data Returned:**
- `asn` (int): Autonomous System Number
- `asn_organization` (string): ASN organization name
- `country_code` (string): 2-letter country code
- `city` (string): City location
- `ip_version` (int): 4 or 6
- `coordinates` (object): Latitude/longitude if available

**Response:**
```json
{
  "ip_address": "192.0.2.1",
  "threat_count": 3,
  "indicators": [/* associated indicators */],
  "enrichment": {
    "asn": 12345,
    "asn_organization": "Example ISP",
    "country_code": "US",
    "city": "New York",
    "coordinates": {
      "latitude": "40.7128",
      "longitude": "-74.0060"
    }
  },
  "query_time": "2025-11-07T20:30:00Z"
}
```

---

### Domain Intelligence

#### Get Domain Intelligence
```
GET /api/v1/domains/{domain}
Tags: Domain Intelligence
Response: DomainIntelligence
Path Parameters:
  - domain (string, required): Domain name
```

**Enrichment Data Returned:**
- `tld` (string): Top-level domain
- `subdomain` (string): Subdomain if present
- `apex_domain` (string): Root domain
- `registrar` (string): Domain registrar
- `creation_date` (datetime): Domain creation date
- `expiration_date` (datetime): Domain expiration date
- `dns_resolves` (bool): Whether domain currently resolves
- `ip_addresses` (string[]): Resolved IPs
- `mx_records` (string[]): Mail exchange records
- `ns_records` (string[]): Nameserver records

---

### File Intelligence

#### Get File Hash Intelligence
```
GET /api/v1/hashes/{file_hash}
Tags: File Intelligence
Response: HashIntelligence
Path Parameters:
  - file_hash (string, required): File hash (MD5, SHA1, or SHA256)
```

**Enrichment Data Returned:**
- `hash_type` (string): Hash algorithm (md5, sha1, sha256)
- `file_name` (string): Associated filename if known
- `file_size` (int): File size in bytes
- `file_type` (string): File type/extension
- `mime_type` (string): MIME type
- `malware_family` (string): Known malware family
- `signature_names` (string[]): Detection signatures
- `detection_ratio` (string): Format like "45/67" (detections/vendors)

---

### Data Sources

#### List Data Sources
```
GET /api/v1/sources
Tags: Sources
Response: SourceInfo[]
Query Parameters:
  - enabled_only (bool): Show only enabled sources (default: true)
```

**Response Fields per Source:**
- `id` (string): Source UUID
- `name` (string): Source name
- `description` (string): Source description
- `source_type` (string): Type (feed, api, file, etc.)
- `enabled` (bool): Source enabled status
- `status` (string): Current status (active, inactive, error, rate_limited)
- `last_collection` (datetime): Last collection timestamp
- `collection_count` (int): Total collections performed
- `error_count` (int): Number of collection errors

---

### Real-Time Feeds

#### Real-Time Threat Feed
```
GET /api/v1/feeds/realtime
Tags: Feeds
Response: StreamingResponse (application/x-ndjson)
```

Streams recent threat indicators in NDJSON format (newline-delimited JSON).

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| indicator_types | string[] | Filter by types |
| threat_types | string[] | Filter by threat types |
| min_severity | int | Minimum severity (1-10) |
| since_minutes | int | Look back period (1-1440 minutes, default: 60) |

**Stream Format:**
Each line is a complete JSON object:
```json
{"id": "uuid", "indicator_type": "ip_address", "value": "192.0.2.1", ...}
{"id": "uuid", "indicator_type": "domain", "value": "malicious.com", ...}
```

**Characteristics:**
- Streaming response (keep-alive connection)
- Server-sent events compatible
- Limited to 1000 most recent indicators per stream

---

### Telemetry - Event Ingestion

#### Ingest Telemetry Batch
```
POST /api/v1/ingest
Tags: Telemetry
Request: TelemetryBatch
Response: TelemetryBatchResponse
```

Ingest security sensor telemetry events in batch.

**Request Body:**
```json
{
  "batch_id": "optional-batch-uuid",
  "events": [
    {
      "sensor_id": "sensor-001",
      "event_type": "process_event",
      "timestamp": "2025-11-07T20:30:00Z",
      "source_host": "host.example.com",
      "event_data": {
        "process_name": "cmd.exe",
        "command_line": "cmd.exe /c whoami",
        "parent_process": "explorer.exe"
      },
      "raw_data": "optional-raw-event-string",
      "severity": 5,
      "tags": ["process", "execution"]
    }
  ]
}
```

**Event Types:**
- `process_event`: Process execution events
- `network_connection`: Network connection events
- `file_change`: File system events
- `user_event`: User activity events
- `system_inventory`: System inventory snapshots
- `authentication`: Authentication events
- `security_event`: Generic security events

**Response:**
```json
{
  "batch_id": "uuid",
  "events_received": 100,
  "events_ingested": 98,
  "errors": [
    "Event 15: Invalid timestamp format"
  ],
  "ingested_at": "2025-11-07T20:30:00Z"
}
```

---

### Telemetry - Event Query

#### Get Telemetry Events
```
GET /api/v1/telemetry/events
Tags: Telemetry
Response: TelemetryEvent[]
```

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| sensor_id | string | Filter by sensor ID |
| event_type | string | Filter by event type |
| start_time | datetime | Events after this time |
| end_time | datetime | Events before this time |
| limit | int | Max events (default: 100, max: 1000) |
| offset | int | Pagination offset (default: 0) |

**Response Fields:**
- `id` (string): Event UUID
- `sensor_id` (string): Originating sensor
- `event_type` (string): Type of event
- `timestamp` (datetime): Event occurrence time
- `source_host` (string): Host where event originated
- `event_data` (object): Event-specific data
- `raw_data` (string): Optional raw event string
- `ingested_at` (datetime): When data was received
- `processed` (bool): Whether event was processed
- `processed_at` (datetime): Processing timestamp
- `severity` (int): 1-10 severity level
- `tags` (string[]): Associated tags

---

#### Get Telemetry Statistics
```
GET /api/v1/telemetry/stats
Tags: Telemetry
Response: Object
```

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| sensor_id | string | Filter by specific sensor |
| hours | int | Time window (default: 24) |

**Response Fields:**
- `time_window_hours` (int): Analysis period
- `total_events` (int): Total events in window
- `active_sensors` (int): Sensors with events
- `events_by_type` (object): Count breakdown by type
- `query_time` (datetime): Query execution time

---

### Sensors - Management & Status

#### List Sensors
```
GET /api/v1/sensors
Tags: Telemetry
Response: SensorMetadata[]
Query Parameters:
  - active_only (bool): Return only active sensors (default: true)
```

**Response Fields per Sensor:**
- `id` (string): Metadata record UUID
- `sensor_id` (string): Unique sensor identifier
- `hostname` (string): Sensor hostname
- `platform` (string): OS platform (Windows, Linux, macOS, etc.)
- `sensor_version` (string): Sensor version
- `first_seen` (datetime): Registration timestamp
- `last_seen` (datetime): Last activity timestamp
- `active` (bool): Current active status
- `total_events` (int): Cumulative events received
- `last_event_at` (datetime): Most recent event timestamp
- `config` (object): Sensor configuration

---

#### Get Specific Sensor
```
GET /api/v1/sensors/{sensor_id}
Tags: Telemetry
Response: SensorMetadata
Path Parameters:
  - sensor_id (string, required): Sensor identifier
```

Returns full metadata for a specific registered sensor.

---

## Data Models & Schemas

### Indicator Types

```python
IndicatorType = Enum:
  - IP_ADDRESS = "ip_address"
  - DOMAIN = "domain"
  - URL = "url"
  - FILE_HASH = "file_hash"
  - EMAIL = "email"
  - CERTIFICATE = "certificate"
  - ASN = "asn"
  - VULNERABILITY = "vulnerability"
```

### Threat Types

```python
ThreatType = Enum:
  - MALWARE = "malware"
  - PHISHING = "phishing"
  - SPAM = "spam"
  - BOTNET = "botnet"
  - EXPLOIT = "exploit"
  - VULNERABILITY = "vulnerability"
  - CERTIFICATE = "certificate"
  - DNS = "dns"
  - NETWORK_SCAN = "network_scan"
  - SUSPICIOUS = "suspicious"
```

### Confidence Levels

```python
ConfidenceLevel = Enum:
  - LOW = "low"
  - MEDIUM = "medium"
  - HIGH = "high"
  - VERIFIED = "verified"
```

### Core Database Tables

#### Indicator
Main table for security indicators (IOCs).

```sql
Columns:
  - id (UUID): Primary key
  - source_id (UUID FK): Data source reference
  - indicator_type (String): Type of indicator
  - value (String): Indicator value
  - normalized_value (String): Normalized for dedup
  - threat_types (JSON): Array of threat types
  - confidence (String): Confidence level
  - severity (Int, 1-10): Severity rating
  - description (Text): Human-readable description
  - tags (JSON): Array of tags
  - first_seen (DateTime): Initial detection
  - last_seen (DateTime): Most recent detection
  - expires_at (DateTime): Expiration timestamp
  - active (Bool): Active status
  - false_positive (Bool): Marked as false positive
  - whitelisted (Bool): Whitelisted indicator
  - raw_data (JSON): Original source data
  - created_at (DateTime): Record creation
  - updated_at (DateTime): Last modification

Indexes:
  - (indicator_type, normalized_value)
  - source_id
  - first_seen, last_seen
  - active, confidence
  - expires_at
```

#### Source
Data source configuration and tracking.

```sql
Columns:
  - id (UUID): Primary key
  - name (String, unique): Source name
  - description (Text): Description
  - url (String): Source URL
  - source_type (String): Type (feed, api, file, etc.)
  - config (JSON): Collection configuration
  - headers (JSON): HTTP headers for requests
  - auth_config (JSON): Authentication details
  - status (String): Current status
  - last_collection (DateTime): Last run time
  - last_success (DateTime): Last successful run
  - last_error (Text): Last error message
  - collection_count (Int): Total collections
  - error_count (Int): Total errors
  - enabled (Bool): Source enabled
  - collection_interval (Int): Seconds between runs
  - rate_limit (Int): Requests per window
  - timeout (Int): Request timeout in seconds
  - retry_attempts (Int): Max retry attempts
  - created_at, updated_at (DateTime)

Indexes:
  - name
  - status
  - enabled
```

#### IPAddress (Type-Specific Enrichment)
IP address specific data.

```sql
Columns:
  - indicator_id (UUID FK): Reference to Indicator
  - ip_address (INET): IP in INET format
  - ip_version (Int): 4 or 6
  - asn (Int): Autonomous System Number
  - asn_organization (String): ASN org name
  - country_code (String, 2): Country code
  - city (String): City location
  - latitude, longitude (String): Geo coordinates
  - network_range (CIDR): Network CIDR block

Indexes:
  - ip_address
  - asn
  - country_code
  - network_range
```

#### Domain (Type-Specific Enrichment)
Domain-specific data.

```sql
Columns:
  - indicator_id (UUID FK): Reference to Indicator
  - domain (String): Domain name
  - tld (String): Top-level domain
  - subdomain (String): Subdomain
  - apex_domain (String): Root domain
  - dns_resolves (Bool): Resolution status
  - ip_addresses (JSON): Resolved IPs
  - mx_records (JSON): MX records
  - ns_records (JSON): Nameservers
  - registrar (String): Domain registrar
  - creation_date (DateTime): Domain creation
  - expiration_date (DateTime): Domain expiration

Indexes:
  - domain
  - tld, apex_domain
  - creation_date, expiration_date
```

#### FileHash (Type-Specific Enrichment)
File hash-specific data.

```sql
Columns:
  - indicator_id (UUID FK): Reference to Indicator
  - hash_value (String): Hash value
  - hash_type (String): md5, sha1, sha256, sha512
  - file_name (String): Associated filename
  - file_size (Int): File size in bytes
  - file_type (String): File type/extension
  - mime_type (String): MIME type
  - malware_family (String): Malware family if known
  - signature_names (JSON): Detection signatures
  - detection_ratio (String): Format "45/67"

Indexes:
  - hash_value
  - hash_type
  - malware_family
```

#### TelemetryEvent
Sensor telemetry events.

```sql
Columns:
  - id (UUID): Primary key
  - sensor_id (String): Sensor identifier
  - event_type (String): Event type
  - timestamp (DateTime): Event time
  - source_host (String): Source hostname
  - event_data (JSON): Event-specific data
  - raw_data (Text): Raw event data
  - ingested_at (DateTime): Ingestion time
  - processed (Bool): Processing status
  - processed_at (DateTime): Processing time
  - severity (Int, 1-10): Severity level
  - tags (JSON): Event tags

Indexes:
  - (sensor_id, timestamp)
  - (event_type, timestamp)
  - ingested_at
  - processed, processed_at
```

#### SensorMetadata
Registered sensor information.

```sql
Columns:
  - id (UUID): Primary key
  - sensor_id (String, unique): Sensor identifier
  - hostname (String): Sensor hostname
  - platform (String): OS platform
  - sensor_version (String): Version number
  - first_seen (DateTime): Registration time
  - last_seen (DateTime): Last heartbeat
  - active (Bool): Active status
  - config (JSON): Sensor configuration
  - total_events (Int): Event count
  - last_event_at (DateTime): Last event time

Indexes:
  - (active, last_seen)
  - sensor_id
```

---

## Query Capabilities

### Full-Text Search
The `/api/v1/indicators/search` endpoint supports full-text search across:
- Indicator value
- Normalized value
- Description

**Example:**
```
GET /api/v1/indicators/search?q=malware&threat_types=malware&active_only=true
```

### Multi-Field Filtering
Combine multiple filters for complex queries:

```
GET /api/v1/indicators/search?
  indicator_type=ip_address&
  min_severity=7&
  confidence=high&
  source_id=abc123&
  since=2025-11-01T00:00:00Z&
  limit=50&offset=100
```

### Type-Specific Queries
Direct queries for specific indicator types:
- `GET /api/v1/ips/{ip_address}` - IP intelligence
- `GET /api/v1/domains/{domain}` - Domain intelligence
- `GET /api/v1/hashes/{file_hash}` - File hash intelligence

### Time-Range Filtering
- `since` parameter: ISO 8601 datetime
- Automatic handling of timezone-aware datetimes
- Default behavior: last seen >= since_date

### Threat Classification
Filter by multiple threat types simultaneously:
```
GET /api/v1/indicators/search?threat_types=malware&threat_types=botnet
```

### Severity Filtering
Range-based filtering:
```
GET /api/v1/indicators/search?min_severity=5&max_severity=10
```

---

## Pagination & Sorting

### Pagination Parameters
- `limit` (int): Results per page
  - Range: 1-10,000
  - Default: 100
  - Max enforced at API level
  
- `offset` (int): Number of records to skip
  - Range: 0+
  - Default: 0
  - Used for cursor-free pagination

### Default Sorting
Most endpoints sort by `last_seen DESC` (most recent first) for indicators.

Telemetry endpoints sort by `timestamp DESC`.

Sensor endpoints sort by `last_seen DESC`.

### Pagination Example
```
# First page
GET /api/v1/indicators/search?limit=100&offset=0

# Second page
GET /api/v1/indicators/search?limit=100&offset=100

# Third page
GET /api/v1/indicators/search?limit=100&offset=200
```

### Response Pagination Fields
All search/list responses include:
```json
{
  "limit": 100,
  "offset": 0,
  "total": 1234,
  "query_time": "2025-11-07T20:30:00Z"
}
```

Use `total` to calculate:
- Total pages: `ceil(total / limit)`
- Has next page: `(offset + limit) < total`

---

## Key Functionality

### 1. Data Aggregation

**Multi-Source Collection:**
- 50+ public threat intelligence sources
- Automated scheduled collection with configurable intervals
- Support for feed, API, file, and custom source types
- Rate limiting and retry mechanisms

**Data Processing Pipeline:**
1. Raw data collection from sources
2. Validation against defined schemas
3. Normalization for consistency
4. Deduplication using fingerprints
5. Enrichment (geo, ASN, WHOIS)
6. Storage in PostgreSQL

**Configuration:**
```
COLLECTION_ENABLED=true
COLLECTION_INTERVAL=3600              # 1 hour
MAX_CONCURRENT_COLLECTORS=10
COLLECTION_TIMEOUT=300                # 5 minutes
SKIP_DUPLICATES=true
VALIDATE_COLLECTION_DATA=true
```

---

### 2. Data Analysis & Enrichment

**Indicator Enrichment:**

**IP Addresses:**
- ASN lookup
- Geographic coordinates
- Country codes
- City information
- Organization identification

**Domains:**
- TLD extraction
- WHOIS data (registrar, dates)
- DNS resolution status
- MX and NS records
- Associated IPs

**File Hashes:**
- Hash type identification
- File metadata
- Malware family classification
- Antivirus signatures
- Detection ratios

**Data Quality:**
- Confidence scoring (low, medium, high, verified)
- Severity rating (1-10 scale)
- Expiration tracking
- False positive marking
- Whitelisting support

---

### 3. Real-Time Reporting

**Dashboard Metrics:**
- Total feeds and active feeds
- New indicator counts (24-hour)
- Trend analysis (% change)
- Last updated timestamp
- Source health status

**Real-Time Feed:**
- Streaming NDJSON format
- 1000 most recent indicators
- Configurable lookback window (1-1440 minutes)
- Filterable by type, threat category, severity
- Keep-alive connection support

---

### 4. Security & Data Management

**Data Lifecycle:**
- `first_seen`: Initial detection
- `last_seen`: Most recent detection
- `expires_at`: Automatic expiration
- `active` flag: Manual lifecycle control
- `false_positive` flag: QA marking
- `whitelisted` flag: Exception marking

**Storage Strategy:**
```
DATA_RETENTION_DAYS=365               # Total retention
ARCHIVE_AFTER_DAYS=90                 # Archive old data
BACKUP_ENABLED=false
BACKUP_INTERVAL=86400                 # 24 hours
BACKUP_RETENTION=30                   # 30 days
```

**Data Normalization:**
- IPs: Standardized format with version detection
- Domains: Lowercase with TLD extraction
- Hashes: Lowercase hex validation
- URLs: Scheme and port normalization
- Timestamps: UTC with timezone awareness

---

### 5. Telemetry Integration

**Event Types Supported:**
- Process execution events
- Network connections
- File system changes
- User activity
- System inventory snapshots
- Authentication events
- Generic security events

**Batch Processing:**
- Configurable batch size (default: 1000)
- Partial success handling (returns errors per item)
- Automatic sensor metadata creation
- Event-to-indicator correlation capability

**Sensor Management:**
- Automatic registration on first ingest
- Activity tracking (first_seen, last_seen)
- Configuration storage per sensor
- Event statistics aggregation

---

### 6. Monitoring & Health

**Health Checks:**
- Simple `/health` endpoint
- Status and version reporting
- Ready for use in Kubernetes probes

**Metrics Available:**
- System statistics (indicator counts, sources)
- Dashboard metrics (feeds, trends)
- Telemetry stats (events by type, active sensors)
- Sensor status and activity

**Logging:**
```
LOG_LEVEL=INFO
LOG_FILE_ENABLED=true
LOG_FILE_PATH=logs/app.log
LOG_JSON_FORMAT=false                 # Can enable for structured logging
SENTRY_ENABLED=false                  # Optional error tracking
```

---

## Error Handling

### HTTP Status Codes
- `200 OK`: Successful GET/POST
- `400 Bad Request`: Invalid parameters, max batch size exceeded
- `404 Not Found`: Indicator/sensor not found
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server-side error

### Error Response Format
```json
{
  "detail": "Error message description",
  "status_code": 400
}
```

### Common Errors

**Batch Size Exceeded:**
```
Status: 400
Detail: "Too many indicators. Maximum allowed: 1000"
```

**Indicator Not Found:**
```
Status: 404
Detail: "Indicator not found"
```

**Invalid Indicator Type:**
```
Status: 400
Detail: "Invalid indicator type"
```

---

## Performance Considerations

### Database Indexes
Optimized for common queries:
- Indicator type + normalized value
- Source ID
- First/last seen timestamps
- Active status
- Confidence levels
- Expiration tracking
- Telemetry sensor + timestamp

### Caching
- Redis support for frequently accessed data
- Configurable cache TTL
- Automatic cache invalidation on updates

### Rate Limiting
Default: 100 requests/60 seconds
- Per-endpoint enforcement
- Can be disabled per config
- Returns 429 status when exceeded

### Response Compression
- GZip compression for responses > 1000 bytes
- Automatic via middleware

---

## Integration Examples

### Retrieve All Malware IPs
```bash
curl "http://localhost:8002/api/v1/indicators/search?indicator_type=ip_address&threat_types=malware&limit=1000"
```

### Check IP Reputation
```bash
curl "http://localhost:8002/api/v1/ips/192.0.2.1"
```

### Bulk Lookup IOCs
```bash
curl -X POST "http://localhost:8002/api/v1/indicators/lookup" \
  -H "Content-Type: application/json" \
  -d '{
    "indicators": [
      {"indicator_type": "ip_address", "value": "192.0.2.1"},
      {"indicator_type": "domain", "value": "example.com"}
    ]
  }'
```

### Real-Time Feed Stream
```bash
curl "http://localhost:8002/api/v1/feeds/realtime?since_minutes=60&min_severity=7" \
  -H "Accept: application/x-ndjson"
```

### Ingest Sensor Events
```bash
curl -X POST "http://localhost:8002/api/v1/ingest" \
  -H "Content-Type: application/json" \
  -d '{
    "batch_id": "batch-001",
    "events": [
      {
        "sensor_id": "sensor-001",
        "event_type": "process_event",
        "timestamp": "2025-11-07T20:30:00Z",
        "source_host": "workstation-01",
        "event_data": {"process_name": "cmd.exe"},
        "severity": 5,
        "tags": ["process"]
      }
    ]
  }'
```

---

## Configuration Summary

### Database
```
DATABASE_URL=postgresql://user:pass@host:5432/db
DB_POOL_SIZE=20
DB_MAX_OVERFLOW=10
DB_POOL_TIMEOUT=30
```

### API Server
```
API_HOST=0.0.0.0
API_PORT=8002
API_WORKERS=4
API_TIMEOUT=30
CORS_ENABLED=true
CORS_ORIGINS=*
```

### Security
```
API_KEY_REQUIRED=false
API_KEY_HEADER=X-API-Key
MAX_BATCH_SIZE=1000
MAX_QUERY_SIZE=10000
RATE_LIMIT_ENABLED=true
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60
```

### Collection
```
COLLECTION_ENABLED=true
COLLECTION_INTERVAL=3600
MAX_CONCURRENT_COLLECTORS=10
COLLECTION_TIMEOUT=300
SKIP_DUPLICATES=true
```

### Storage
```
DATA_RETENTION_DAYS=365
ARCHIVE_AFTER_DAYS=90
BACKUP_ENABLED=false
BACKUP_INTERVAL=86400
```

