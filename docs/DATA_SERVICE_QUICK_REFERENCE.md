# Data Service - Quick Reference

## API Endpoints Summary

### Health & System

| Method | Path | Purpose | Auth | Rate Limited |
|--------|------|---------|------|--------------|
| GET | /health | Health check | No | Yes |
| GET | /api/v1/stats | System statistics | Optional | Yes |
| GET | /api/v1/dashboard/threat-intel | Dashboard metrics | Optional | Yes |

### Indicators (IOCs)

| Method | Path | Purpose | Query Parameters | Auth |
|--------|------|---------|------------------|------|
| GET | /api/v1/indicators/search | Search indicators | q, indicator_type, threat_types, confidence, min_severity, max_severity, source_id, since, active_only, limit, offset | Optional |
| GET | /api/v1/indicators/{id} | Get indicator details | None | Optional |
| POST | /api/v1/indicators/lookup | Bulk lookup (max 1000) | None (body params) | Optional |

### Type-Specific Intelligence

| Method | Path | Purpose | Parameter | Enrichment |
|--------|------|---------|-----------|-----------|
| GET | /api/v1/ips/{ip} | IP reputation | IPv4/IPv6 | ASN, geo, country, city, coords |
| GET | /api/v1/domains/{domain} | Domain intelligence | domain name | TLD, registrar, DNS, WHOIS dates |
| GET | /api/v1/hashes/{hash} | File hash intelligence | MD5/SHA1/SHA256 | Malware family, signatures, detection ratio |

### Data Sources & Feeds

| Method | Path | Purpose | Parameters | Notes |
|--------|------|---------|-----------|-------|
| GET | /api/v1/sources | List sources | enabled_only (bool) | Returns source config and status |
| GET | /api/v1/feeds/realtime | Real-time feed stream | indicator_types[], threat_types[], min_severity, since_minutes | NDJSON streaming format |

### Telemetry (Sensors & Events)

| Method | Path | Purpose | Parameters |
|--------|------|---------|-----------|
| POST | /api/v1/ingest | Batch ingest events | batch_id, events[] |
| GET | /api/v1/telemetry/events | Query events | sensor_id, event_type, start_time, end_time, limit, offset |
| GET | /api/v1/telemetry/stats | Event statistics | sensor_id, hours |
| GET | /api/v1/sensors | List sensors | active_only (bool) |
| GET | /api/v1/sensors/{id} | Sensor details | sensor_id |

---

## Response Patterns

### Search/List Pagination
```json
{
  "data": [...],
  "total": 1234,
  "limit": 100,
  "offset": 0,
  "query_time": "2025-11-07T20:30:00Z"
}
```

### Error Response
```json
{
  "detail": "Error message",
  "status_code": 400
}
```

---

## Key Indicator Fields

### Required Fields
- `id`: UUID
- `indicator_type`: ip_address, domain, file_hash, url, email, certificate, asn, vulnerability
- `value`: Indicator value
- `source_id`: UUID of originating source

### Core Fields
- `threat_types`: [malware, phishing, spam, botnet, exploit, vulnerability, certificate, dns, network_scan, suspicious]
- `confidence`: low, medium, high, verified
- `severity`: 1-10 scale
- `description`: Human-readable text
- `tags`: String array

### Temporal Fields
- `first_seen`: Initial detection timestamp
- `last_seen`: Most recent detection timestamp
- `expires_at`: Expiration timestamp
- `created_at`: Record creation time
- `updated_at`: Last modification time

### Status Fields
- `active`: Boolean (default: true)
- `false_positive`: Boolean (default: false)
- `whitelisted`: Boolean (default: false)

---

## Event Types (Telemetry)

- `process_event`: Process execution
- `network_connection`: Network activity
- `file_change`: File system events
- `user_event`: User activity
- `system_inventory`: System info snapshots
- `authentication`: Auth events
- `security_event`: Generic security events

---

## Severity Scale

| Level | Meaning |
|-------|---------|
| 1-3 | Low risk |
| 4-6 | Medium risk |
| 7-8 | High risk |
| 9-10 | Critical |

---

## Rate Limiting Defaults

- 100 requests per 60 seconds (configurable)
- Max batch size: 1000 items
- Max query size: 10,000 characters
- Returns 429 status when exceeded

---

## Authentication

- **Type**: Optional API Key (configurable)
- **Header**: X-API-Key (configurable)
- **Status**: Disabled by default (API_KEY_REQUIRED=false)
- **Enable**: Set API_KEY_REQUIRED=true in config

---

## Pagination Guide

```
# Request structure
GET /api/v1/indicators/search?limit=100&offset=0

# Calculate pages
total_pages = ceil(response.total / limit)
has_next = (offset + limit) < total
next_offset = offset + limit
```

**Example:**
- Total: 1234 records
- Limit: 100
- Total pages: ceil(1234/100) = 13
- Page 1: offset=0, Page 2: offset=100, etc.

---

## Field Filters (Search Endpoint)

| Filter | Type | Example | Notes |
|--------|------|---------|-------|
| q | string | "malware.com" | Full-text search |
| indicator_type | string | "domain" | Single type only |
| threat_types | string[] | ["malware", "botnet"] | Multiple values |
| confidence | string | "high" | Single value |
| min_severity | int | 7 | Inclusive |
| max_severity | int | 10 | Inclusive |
| source_id | UUID | "abc-123..." | Exact match |
| since | datetime | "2025-11-01T00:00:00Z" | ISO 8601 |
| active_only | bool | true | Default: true |

---

## Database Schema Overview

### Tables
1. **indicators** - Main IOC table (with unique constraint on source_id + type + value)
2. **sources** - Data source definitions
3. **ip_addresses** - IP enrichment (1:1 with indicators)
4. **domains** - Domain enrichment (1:1 with indicators)
5. **file_hashes** - Hash enrichment (1:1 with indicators)
6. **enrichments** - Generic enrichment (1:many with indicators)
7. **telemetry_events** - Sensor events
8. **sensor_metadata** - Registered sensors
9. **collection_runs** - Collection job tracking

### Key Indexes
- indicators: (type, normalized_value), source_id, first_seen, last_seen, active, confidence, expires_at
- sources: name, status, enabled
- ip_addresses: ip_address, asn, country_code, network_range
- domains: domain, tld, apex_domain, creation_date, expiration_date
- file_hashes: hash_value, hash_type, malware_family
- telemetry_events: (sensor_id, timestamp), (event_type, timestamp), ingested_at, (processed, processed_at)
- sensor_metadata: sensor_id, (active, last_seen)

---

## Configuration Essentials

### Required
```
DATABASE_URL=postgresql://user:pass@host:5432/db
```

### Important Security
```
API_KEY_REQUIRED=false (set true for production)
MAX_BATCH_SIZE=1000
RATE_LIMIT_ENABLED=true
```

### Tuning
```
COLLECTION_INTERVAL=3600
MAX_CONCURRENT_COLLECTORS=10
DATA_RETENTION_DAYS=365
API_WORKERS=4
```

---

## Common Query Examples

### Find all malicious IPs with high severity
```
GET /api/v1/indicators/search?
  indicator_type=ip_address&
  threat_types=malware&
  min_severity=8&
  confidence=high&
  limit=1000
```

### Get recent indicators from last 24 hours
```
GET /api/v1/indicators/search?
  since=2025-11-06T00:00:00Z&
  limit=500
```

### Search across all indicators
```
GET /api/v1/indicators/search?
  q=example&
  limit=100&
  offset=0
```

### Get domain intelligence with enrichment
```
GET /api/v1/domains/example.com
```

### Bulk IOC lookup
```
POST /api/v1/indicators/lookup
Content-Type: application/json

{
  "indicators": [
    {"indicator_type": "ip_address", "value": "192.0.2.1"},
    {"indicator_type": "domain", "value": "example.com"},
    {"indicator_type": "file_hash", "value": "d41d8cd98f00b204e9800998ecf8427e"}
  ]
}
```

### Stream real-time threats
```
GET /api/v1/feeds/realtime?
  since_minutes=60&
  min_severity=7&
  threat_types=malware
```

### Ingest telemetry from sensor
```
POST /api/v1/ingest
Content-Type: application/json

{
  "batch_id": "batch-20251107-001",
  "events": [
    {
      "sensor_id": "sensor-001",
      "event_type": "process_event",
      "timestamp": "2025-11-07T20:30:00Z",
      "source_host": "workstation-01",
      "event_data": {"process_name": "cmd.exe", "parent": "explorer.exe"},
      "severity": 5,
      "tags": ["process", "execution"]
    }
  ]
}
```

