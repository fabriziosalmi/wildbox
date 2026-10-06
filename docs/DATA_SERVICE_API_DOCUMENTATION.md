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

- **Threat Intelligence Collection**: Scheduled collection from the sources in the database; `manage.py sources add-defaults` adds the default one
- **Data Aggregation**: Centralized repository for security indicators
- **Per-type fields**: the IP version, a domain's TLD, apex domain and subdomain, and a hash's algorithm, derived from the value; no geographic, ASN or WHOIS lookup is made
- **Real-time Feeds**: Live threat intelligence streaming
- **Telemetry Ingestion**: Security sensor event processing

**Service Details:**

- Framework: FastAPI (service version 0.1.6)
- Database: PostgreSQL with SQLAlchemy ORM
- API Port: 8002 (default)
- Base Path: `/api/v1`

---

## Authentication & Security

### Current Implementation

- **Gateway only**: clients reach the service through the API gateway, at
  `https://<host>/api/v1/data/...` (proxied to the service's `/api/v1/...`)
  and `https://<host>/api/v1/data/health` (proxied to `/health`). The
  gateway authenticates every one of these routes, health included, with a
  JWT bearer token or an API key sent as `X-API-Key`. There is no anonymous
  access.
- **Proof of origin**: the gateway forwards the caller as
  `X-Wildbox-User-ID`, `X-Wildbox-Team-ID` and `X-Wildbox-Role` with the
  `X-Gateway-Secret` header. Every `/api/v1` route depends on
  `get_current_user`, or `get_ingest_user` for `POST /api/v1/ingest`
  (`app/auth.py`): `open_security_shared.gateway_auth.require_scope` over
  `get_user_from_gateway_headers`. It answers 403 to a request without the
  user and team headers, with a wrong secret or without
  `X-Wildbox-Auth-Type`, and 503 when `GATEWAY_INTERNAL_SECRET` is not set.
  `/health` and `/metrics` have no such dependency, nor do `/docs`, `/redoc`
  and `/openapi.json`, which exist only when `ENVIRONMENT` is `development`.
- **No service API key**: `API_KEY_REQUIRED` and `API_KEY_HEADER` were
  removed from `app/config.py` because nothing read them.
- **Team scope**: indicators and sources are filtered to the caller's team
  plus the global (`team_id IS NULL`) rows. Telemetry events and sensors
  belong to the team of the credential they were ingested with and are
  filtered to the caller's team only, with no global rows; rows stored
  before telemetry had a team (`team_id IS NULL`) are visible to no team.
- **API key scopes** (checked by the gateway, and again by the service): `read` for `GET`, `write` for
  `POST`. `POST /api/v1/data/ingest` takes `data:ingest`, `data:write` or
  `write`; `data:ingest` allows that route only, and is the scope of the key
  a sensor sends telemetry with.
- **Rate limiting**: none in the service; `RATE_LIMIT_ENABLED`,
  `RATE_LIMIT_REQUESTS` and `RATE_LIMIT_WINDOW` are read into the
  configuration and used by nothing. The gateway limits each team to
  `RATE_LIMIT_PER_HOUR` requests per hour (default 10000), enforced in
  fixed 60-second windows of one sixtieth of that (166 by default).
- **Batch operations**: limited by `MAX_BATCH_SIZE` (default 1000) and by
  the request schemas (1000 items).
- **CORS**: configurable with an origins allow list.

### Security Configuration

```text
GATEWAY_INTERNAL_SECRET=...              # Shared with the gateway; required
MAX_BATCH_SIZE=1000                      # Max items in batch operations
```

### Data Validation

- Input validation for all indicator types (IP, domain, hash, etc.)
- Normalized value storage for deduplication
- Request bodies and query parameters are validated by the Pydantic schemas in `app/schemas/api.py` and the `Query` bounds of each route

---

## API Endpoints by Category

### Health & Monitoring

#### Health Check

```http
GET /health
Tags: Health
Response: Object
```

Returns the service status. Through the gateway it is
`GET /api/v1/data/health`, which requires authentication.

**Response Example:**

```json
{
  "status": "healthy",
  "timestamp": "2025-11-07T20:30:00+00:00"
}
```

---

### Statistics & Dashboard

#### System Statistics

```http
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

```http
GET /api/v1/dashboard/threat-intel
Tags: Dashboard
Response: Object
```

Dashboard-optimized threat intelligence metrics with trends. Every figure
covers the caller's team and the global feeds, the same scope as
`/api/v1/indicators/search`.

**Response Fields:**

- `total_feeds` (int): Total configured feeds
- `active_feeds` (int): Active feeds
- `last_updated` (datetime or null): End of the last completed collection
  run of a visible feed; null when none has completed
- `new_indicators` (int): New indicators in last 24 hours
- `trends_change` (float or null): Percentage change of `new_indicators`
  vs the previous 24 hours, one decimal (-100.0 when the last 24 hours had
  none); null when the previous 24 hours had no indicators, since a change
  from zero has no percentage

---

### Indicators - Search & Query

#### Search Indicators

```http
GET /api/v1/indicators/search
Tags: Indicators
Response: IndicatorSearchResponse
```

**Query Parameters:**

| Parameter | Type | Description | Default |
| ----------- | ------ | ------------- | --------- |
| q | string | Case-insensitive substring of the value, the normalized value or the description | None |
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

```http
GET /api/v1/indicators/{indicator_id}
Tags: Indicators
Response: IndicatorDetail
Path Parameters:
  - indicator_id (string, required): UUID of indicator
```

Returns the indicator with the per-type row stored for it (see the enrichment fields of each lookup below).

**Response Includes:**

- Base indicator fields (from IndicatorResponse)
- `enrichment` (object): Type-specific enrichment data
- `raw_data` (object): Original source data

---

#### Bulk Indicator Lookup

```http
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

```http
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
- `coordinates` (object): Latitude/longitude if available

The service fills what it can derive from the value alone: `ip_version` for an
IP address; `tld`, `subdomain` and `apex_domain` for a domain; `hash_type` for a
file hash. Nothing in the service looks up or writes the other fields, so they
are empty on every indicator it collects.

`ip_version` is in the enrichment of `GET /api/v1/indicators/{indicator_id}`,
not in this one.

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

```http
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

The service fills what it can derive from the value alone: `ip_version` for an
IP address; `tld`, `subdomain` and `apex_domain` for a domain; `hash_type` for a
file hash. Nothing in the service looks up or writes the other fields, so they
are empty on every indicator it collects.

This endpoint returns `tld`, `registrar`, `creation_date`, `expiration_date`,
`ip_addresses`, `mx_records` and `ns_records`; `subdomain`, `apex_domain` and
`dns_resolves` are only in the enrichment of
`GET /api/v1/indicators/{indicator_id}`.

---

### File Intelligence

#### Get File Hash Intelligence

```http
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

The service fills what it can derive from the value alone: `ip_version` for an
IP address; `tld`, `subdomain` and `apex_domain` for a domain; `hash_type` for a
file hash. Nothing in the service looks up or writes the other fields, so they
are empty on every indicator it collects.

`mime_type` is only in the enrichment of
`GET /api/v1/indicators/{indicator_id}`, not in this endpoint's.

---

### Data Sources

#### List Data Sources

```http
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

```http
GET /api/v1/feeds/realtime
Tags: Feeds
Response: StreamingResponse (application/x-ndjson)
```

Streams recent threat indicators in NDJSON format (newline-delimited JSON).

**Query Parameters:**

| Parameter | Type | Description |
| ----------- | ------ | ------------- |
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

- Computed once and returned as NDJSON; not a long-lived stream
- Limited to 1000 most recent indicators per response

---

### Telemetry - Event Ingestion

#### Ingest Telemetry Batch

```http
POST /api/v1/ingest
Tags: Telemetry
Request: TelemetryBatch
Response: TelemetryBatchResponse
```

Ingest security sensor telemetry events in batch, through the gateway at
`POST https://<host>/api/v1/data/ingest`. The sensor sends its batches there
with an identity API key in `X-API-Key` scoped to `data:ingest`. The events
and the sensor's record are stored under the caller's team; the body carries
no team, and a team named in it is ignored. A sensor's `sensor_id` is unique
within its team.

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
  "events_ingested": 100,
  "errors": [],
  "ingested_at": "2025-11-07T20:30:00Z"
}
```

A batch is stored whole or not at all. A 200 means every event was stored,
so `events_ingested` equals `events_received` and `errors` is empty. A batch
with an invalid event answers 422 for the whole batch, naming the event by
its index; a database error that may pass answers 503 with `Retry-After: 5`,
so that the sensor sends the batch again. The answers are listed in
[the data reference](api/data/endpoints.md).

---

### Telemetry - Event Query

#### Get Telemetry Events

```http
GET /api/v1/telemetry/events
Tags: Telemetry
Response: TelemetryEvent[]
```

**Query Parameters:**

The caller's team's events only.

| Parameter | Type | Description |
| ----------- | ------ | ------------- |
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

```http
GET /api/v1/telemetry/stats
Tags: Telemetry
Response: Object
```

Counts cover the caller's team's telemetry only.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| sensor_id | string | Filter by specific sensor |
| hours | int | Time window (default: 24) |

**Response Fields:**

- `time_window_hours` (int): Analysis period
- `total_events` (int): Total events in window
- `active_sensors` (int): The team's active sensors last seen within the window, whatever `sensor_id` is
- `events_by_type` (object): Count breakdown by type
- `query_time` (datetime): Query execution time

---

### Sensors - Management & Status

#### List Sensors

```http
GET /api/v1/sensors
Tags: Telemetry
Response: SensorMetadata[]
Query Parameters:
  - active_only (bool): Return only active sensors (default: true)
```

The caller's team's sensors only.

**Response Fields per Sensor:**

- `id` (string): Metadata record UUID
- `sensor_id` (string): Sensor identifier, unique within the team
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

```http
GET /api/v1/sensors/{sensor_id}
Tags: Telemetry
Response: SensorMetadata
Path Parameters:
  - sensor_id (string, required): Sensor identifier
```

Returns full metadata for one of the caller's team's sensors; 404 when the
team has no sensor by that ID, including when another team has one.

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
  - team_id (UUID, nullable): Owning team; NULL rows are visible to no team
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
  - (team_id, timestamp)
  - (event_type, timestamp)
  - ingested_at
  - processed, processed_at
```

#### SensorMetadata

Registered sensor information.

```sql
Columns:
  - id (UUID): Primary key
  - team_id (UUID, nullable): Owning team; NULL rows are visible to no team
  - sensor_id (String): Sensor identifier, unique per team
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
  - team_id, sensor_id
  - UNIQUE (team_id, sensor_id)
```

---

## Query Capabilities

### Substring Search

The `/api/v1/indicators/search` endpoint matches `q` as a case-insensitive substring of:

- Indicator value
- Normalized value
- Description

**Example:**

```http
GET /api/v1/indicators/search?q=malware&threat_types=malware&active_only=true
```

### Multi-Field Filtering

Combine multiple filters for complex queries:

```http
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

```http
GET /api/v1/indicators/search?threat_types=malware&threat_types=botnet
```

### Severity Filtering

Range-based filtering:

```http
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

```http
# First page
GET /api/v1/indicators/search?limit=100&offset=0

# Second page
GET /api/v1/indicators/search?limit=100&offset=100

# Third page
GET /api/v1/indicators/search?limit=100&offset=200
```

### Response Pagination Fields

`GET /api/v1/indicators/search` is the only response with pagination fields
(`GET /api/v1/telemetry/events` takes `limit` and `offset` and returns a bare
array with no total; `GET /api/v1/sources` and `GET /api/v1/sensors` return
every row as a bare array):

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

- Collectors for seven feeds (`app/collectors/sources.py`): Malware Domain List, AbuseIPDB, URLVoid, PhishTank, Feodo Tracker, MalwareBazaar and ThreatFox. A source's `source_type` names its collector; a type without one is not collected
- One default source, Feodo Tracker (`app/collectors/defaults.py`), which needs no key
- Scheduled collection, at each source's own interval
- Per-source rate limiting; no retry

**Data Processing Pipeline:**

1. Raw data collection from sources
2. Validation against defined schemas
3. Normalization for consistency
4. Deduplication by source, indicator type and normalized value
5. The per-type row derived from the value (IP version; TLD, apex domain and subdomain; hash algorithm)
6. Storage in PostgreSQL

**Configuration:**

```text
MAX_CONCURRENT_COLLECTORS=10          # sources collected at the same time
```

A source's interval, timeout and rate limit are fields of the source
record. `COLLECTION_ENABLED`, `COLLECTION_INTERVAL`,
`COLLECTION_TIMEOUT`, `SKIP_DUPLICATES` and `VALIDATE_COLLECTION_DATA` were
listed here and read by no code; they are not settings.

---

### 2. Data Analysis & Enrichment

**Indicator Enrichment:**

**IP Addresses:** the IP version.

**Domains:** the TLD, the apex domain and the subdomain.

**File Hashes:** the hash algorithm.

These are derived from the indicator's value when it is collected. The other
columns of the per-type tables (ASN, organization, country, city,
coordinates; registrar, dates, DNS records; file metadata, malware family,
signatures, detection ratio) are returned by the API and written by nothing
in the service.

**Data Quality:**

- Confidence scoring (low, medium, high, verified)
- Severity rating (1-10 scale)
- Expiration tracking

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
- `expires_at`: set by the collector from the source; nothing deactivates an indicator when it passes
- `active`, `false_positive`, `whitelisted`: columns; no route or command changes them, and only `active` is read (searches and lookups return active indicators)

**Storage:**

The service has no retention, archive or backup setting of its own:
`DATA_RETENTION_DAYS`, `ARCHIVE_AFTER_DAYS` and `BACKUP_*` were listed here
and read by no code.

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
- A batch is stored whole or not at all; an invalid event is named by its index in a 422
- Automatic sensor metadata creation

**Sensor Management:**

- Automatic registration on first ingest, under the ingesting team
- Activity tracking (first_seen, last_seen)
- Configuration storage per sensor
- Event statistics aggregation

---

### 6. Monitoring & Health

**Health Checks:**

- Simple `/health` endpoint
- Status and timestamp in the body; the service version is the `X-API-Version` header of every response
- Ready for use in Kubernetes probes

**Metrics Available:**

- System statistics (indicator counts, sources)
- Dashboard metrics (feeds, trends)
- Telemetry stats (events by type, active sensors)
- Sensor status and activity

**Logging:**

```text
LOG_LEVEL=INFO
LOG_FORMAT="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
```

The service logs to the console. It writes no log file and has no Sentry
integration: `LOG_FILE_*`, `LOG_JSON_FORMAT` and `SENTRY_*` were not read.

---

## Error Handling

### HTTP Status Codes

- `200 OK`: Successful GET/POST
- `400 Bad Request`: Max batch size exceeded
- `403 Forbidden`: Request without the gateway headers or secret, without
  `X-Wildbox-Auth-Type`, or from an API key without the scope (the gateway's
  own 401/403 answers come first for a client)
- `404 Not Found`: Indicator/sensor not found, or not visible to the caller
- `422 Unprocessable Entity`: Invalid parameter or request body
- `429 Too Many Requests`: Gateway per-team rate limit exceeded (the service
  has no limit of its own)
- `500 Internal Server Error`: Server-side error
- `503 Service Unavailable`: Telemetry batch not stored; send it again

### Error Response Format

The canonical shape of `open_security_shared.errors`:

```json
{
  "error": {
    "code": 404,
    "message": "Indicator not found",
    "type": "HTTPException",
    "request_id": "..."
  }
}
```

### Common Errors

**Batch Size Exceeded:** more than 1000 items answer 422 (`Request validation
failed`). A 400 is answered only when `MAX_BATCH_SIZE` is set lower than 1000,
for example with `MAX_BATCH_SIZE=500`:

```yaml
Status: 400
Detail: "Too many indicators. Maximum allowed: 500"
```

**Indicator Not Found:**

```yaml
Status: 404
Detail: "Indicator not found"
```

**Invalid Indicator Type (bulk lookup):**

```yaml
Status: 422
Message: "Request validation failed"
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

The service has no cache and does not use Redis.

### Rate Limiting

The service enforces no rate limit; its `RATE_LIMIT_*` settings are unused.
The gateway limits each team to `RATE_LIMIT_PER_HOUR` requests per hour
(default 10000, in fixed 60-second windows of one sixtieth of that) and
answers 429 past it. A value of `RATE_LIMIT_PER_HOUR` that is not a whole
number from 1 to 1000000000 stops the gateway at startup.

### Response Compression

- GZip compression for responses > 1000 bytes
- Automatic via middleware

---

## Integration Examples

Every example goes through the gateway with a token from
`POST https://<host>/auth/jwt/login` (or an API key sent as `X-API-Key`).

```bash
CA=open-security-gateway/ssl/wildbox.crt
AUTH="Authorization: Bearer $TOKEN"
```

### Retrieve All Malware IPs

```bash
curl -s --cacert "$CA" -H "$AUTH" \
  "https://<host>/api/v1/data/indicators/search?indicator_type=ip_address&threat_types=malware&limit=1000"
```

### Check IP Reputation

```bash
curl -s --cacert "$CA" -H "$AUTH" "https://<host>/api/v1/data/ips/192.0.2.1"
```

### Bulk Lookup IOCs

```bash
curl -s --cacert "$CA" -H "$AUTH" -X POST "https://<host>/api/v1/data/indicators/lookup" \
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
curl -s --cacert "$CA" -H "$AUTH" \
  "https://<host>/api/v1/data/feeds/realtime?since_minutes=60&min_severity=7"
```

### Ingest Sensor Events

The sensor sends its batches this way, with a team member's identity API
key scoped to `data:ingest`; the events are stored under that team.

```bash
curl -s --cacert "$CA" -H "X-API-Key: $SENSOR_DATA_LAKE_API_KEY" \
  -X POST "https://<host>/api/v1/data/ingest" \
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

```text
DATABASE_URL=postgresql://user:pass@host:5432/db
DB_POOL_SIZE=20
DB_POOL_OVERFLOW=10
DB_POOL_TIMEOUT=30
```

### API Server

```text
API_HOST=0.0.0.0
API_PORT=8002
CORS_ENABLED=true
CORS_ORIGINS=http://localhost:3000   # comma-separated; empty allows no origin
```

### Security

```text
GATEWAY_INTERNAL_SECRET=...   # Required; shared with the gateway
MAX_BATCH_SIZE=1000
```

### Collection

```text
MAX_CONCURRENT_COLLECTORS=10
```

These are all the settings the service reads, with `ENVIRONMENT`, `DEBUG`,
`SECRET_KEY`, `DB_ECHO`, `LOG_LEVEL` and `LOG_FORMAT`
(`open-security-data/.env.example`).

