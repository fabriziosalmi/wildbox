# Data Service API

**Service Port**: 8006
**Base URL**: `http://localhost:8006/api/v1`
**Authentication**: Optional (API Key for enhanced features)
**Documentation**: [Live Swagger UI](http://localhost:8006/docs) | [OpenAPI Schema](http://localhost:8006/openapi.json)

---

## Overview

The Data Service aggregates, normalizes, and provides access to security intelligence data from 50+ threat intelligence sources. It maintains a data lake of indicators of compromise (IOCs), enriches them with geolocation and WHOIS information, and provides powerful query and filtering capabilities for security analysis.

## Table of Contents

- [Authentication](#authentication)
- [Indicators Search](#indicators-search)
- [Intelligence Lookups](#intelligence-lookups)
- [Sources & Feeds](#sources--feeds)
- [Telemetry](#telemetry)
- [Error Codes](#error-codes)
- [Rate Limiting](#rate-limiting)

---

## Authentication

### Optional API Key Authentication

Use an optional API key to unlock enhanced features and higher rate limits:

```bash
curl -X GET "http://localhost:8006/api/v1/indicators/search" \
  -H "X-API-Key: your-api-key"
```

### No Authentication Required

Public endpoints work without authentication:

```bash
curl -X GET "http://localhost:8006/api/v1/indicators/search?q=example.com"
```

---

## Indicators Search

### GET /indicators/search

Search for indicators of compromise in the threat intelligence database.

**Method**: `GET`
**Endpoint**: `/api/v1/indicators/search`
**Authentication**: Optional (API Key for higher limits)
**Rate Limit**: 100 requests/minute

**Query Parameters**:

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| q | string | Yes | - | Search query (IP, domain, hash, URL, email) |
| type | string | No | - | Filter by type: ipv4, ipv6, domain, url, md5, sha1, sha256, email |
| threat_level | string | No | - | Filter by threat: malware, phishing, botnet, ransomware, etc. |
| confidence | float | No | - | Minimum confidence score (0.0-1.0) |
| severity | string | No | - | Filter by severity: critical, high, medium, low, info |
| source | string | No | - | Filter by data source name |
| limit | integer | No | 20 | Number of results (max: 10,000) |
| offset | integer | No | 0 | Pagination offset |
| sort | string | No | -last_seen | Sort by field (use - for descending) |
| active_only | boolean | No | true | Only return currently active indicators |

**Request**:
```bash
curl -X GET "http://localhost:8006/api/v1/indicators/search?q=malicious-domain.com&limit=20" \
  -H "X-API-Key: your-api-key"
```

**Response (200 OK)**:
```json
{
  "count": 1,
  "next": null,
  "previous": null,
  "results": [
    {
      "id": "ind-001",
      "type": "domain",
      "value": "malicious-domain.com",
      "threat_level": "malware",
      "confidence": 0.95,
      "severity": "critical",
      "last_seen": "2024-11-07T16:30:00Z",
      "first_seen": "2024-10-15T08:00:00Z",
      "sources": ["AlienVault OTX", "Abuse.ch"],
      "status": "active",
      "tags": ["botnet", "c2", "apt"]
    }
  ],
  "pagination": {
    "limit": 20,
    "offset": 0,
    "total": 1
  }
}
```

---

### POST /indicators/bulk-lookup

Perform bulk lookup of multiple indicators at once.

**Method**: `POST`
**Endpoint**: `/api/v1/indicators/bulk-lookup`
**Authentication**: Optional

**Request Body**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| indicators | array | Yes | Array of indicator values (max: 1,000) |
| include_enrichment | boolean | No | Include WHOIS/geolocation data (default: false) |

**Request**:
```bash
curl -X POST http://localhost:8006/api/v1/indicators/bulk-lookup \
  -H "Content-Type: application/json" \
  -d '{
    "indicators": ["8.8.8.8", "example.com", "192.168.1.1"],
    "include_enrichment": true
  }'
```

**Response (200 OK)**:
```json
{
  "results": [
    {
      "value": "8.8.8.8",
      "type": "ipv4",
      "found": true,
      "threat_level": "benign",
      "confidence": 1.0,
      "enrichment": {
        "asn": "AS15169",
        "organization": "Google LLC",
        "country": "US",
        "is_public": true
      }
    },
    {
      "value": "example.com",
      "type": "domain",
      "found": false
    }
  ]
}
```

---

## Intelligence Lookups

### GET /intelligence/ip/{ip}

Get detailed threat intelligence for an IP address.

**Method**: `GET`
**Endpoint**: `/api/v1/intelligence/ip/{ip}`
**Authentication**: Optional

**Path Parameters**:

| Name | Type | Description |
|------|------|-------------|
| ip | string | IPv4 or IPv6 address |

**Request**:
```bash
curl -X GET http://localhost:8006/api/v1/intelligence/ip/192.168.1.100
```

**Response (200 OK)**:
```json
{
  "ip": "192.168.1.100",
  "reputation_score": 45,
  "threat_indicators": [
    {
      "source": "AlienVault",
      "type": "spam",
      "last_reported": "2024-11-05T10:00:00Z"
    }
  ],
  "geolocation": {
    "country": "US",
    "city": "Los Angeles",
    "latitude": 34.0522,
    "longitude": -118.2437
  },
  "asn": {
    "asn": "AS15169",
    "organization": "Google LLC",
    "prefix": "8.8.8.0/24"
  },
  "whois": {
    "registrar": "ARIN",
    "created_date": "2010-01-01",
    "updated_date": "2024-01-01"
  },
  "is_public": true,
  "is_hosting": true
}
```

---

### GET /intelligence/domain/{domain}

Get detailed threat intelligence for a domain.

**Method**: `GET`
**Endpoint**: `/api/v1/intelligence/domain/{domain}`
**Authentication**: Optional

**Path Parameters**:

| Name | Type | Description |
|------|------|-------------|
| domain | string | Domain name (FQDN) |

**Request**:
```bash
curl -X GET http://localhost:8006/api/v1/intelligence/domain/example.com
```

**Response (200 OK)**:
```json
{
  "domain": "example.com",
  "reputation_score": 95,
  "threat_indicators": [],
  "whois": {
    "registrar": "VeriSign Global Registry Services",
    "registrant_name": "IANA Domains",
    "created_date": "1995-01-31",
    "expires_date": "2024-12-31",
    "name_servers": [
      "a.iana-servers.net",
      "b.iana-servers.net"
    ]
  },
  "dns": {
    "a_records": ["93.184.216.34"],
    "mx_records": ["mail.example.com"],
    "ns_records": ["a.iana-servers.net", "b.iana-servers.net"]
  },
  "ssl_certificate": {
    "issuer": "DigiCert",
    "valid_from": "2024-01-01",
    "valid_to": "2025-01-01",
    "san": ["www.example.com"]
  },
  "is_sinkhole": false,
  "is_dga": false
}
```

---

### GET /intelligence/hash/{hash}

Get detailed threat intelligence for a file hash.

**Method**: `GET`
**Endpoint**: `/api/v1/intelligence/hash/{hash}`
**Authentication**: Optional

**Path Parameters**:

| Name | Type | Description |
|------|------|-------------|
| hash | string | MD5, SHA1, or SHA256 file hash |

**Request**:
```bash
curl -X GET http://localhost:8006/api/v1/intelligence/hash/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

**Response (200 OK)**:
```json
{
  "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "hash_type": "sha256",
  "threat_level": "malware",
  "confidence": 0.98,
  "first_submission": "2024-01-15T10:30:00Z",
  "last_analysis": "2024-11-07T16:00:00Z",
  "detections": 45,
  "submissions": 123,
  "file_name": "trojan.exe",
  "file_size": 1024000,
  "file_type": "PE32 executable",
  "magic": "7F45 4C46",
  "threat_names": [
    "Trojan.Win32.Generic",
    "Backdoor.Win32.Agent"
  ],
  "file_tags": ["trojan", "backdoor", "executable"]
}
```

---

## Sources & Feeds

### GET /sources

List all configured threat intelligence sources and feeds.

**Method**: `GET`
**Endpoint**: `/api/v1/sources`
**Authentication**: Optional

**Query Parameters**:

| Name | Type | Description |
|------|------|-------------|
| limit | integer | Results per page (default: 50) |
| offset | integer | Pagination offset |

**Request**:
```bash
curl -X GET http://localhost:8006/api/v1/sources?limit=20
```

**Response (200 OK)**:
```json
{
  "count": 52,
  "results": [
    {
      "id": "src-001",
      "name": "AlienVault OTX",
      "description": "Open Threat Exchange - Open source threat intelligence",
      "source_type": "commercial",
      "url": "https://otx.alienvault.com",
      "last_update": "2024-11-07T18:00:00Z",
      "indicators_count": 125000,
      "reliability_score": 0.95
    },
    {
      "id": "src-002",
      "name": "Abuse.ch URLhaus",
      "description": "Database of malicious URLs",
      "source_type": "open_source",
      "url": "https://urlhaus.abuse.ch",
      "last_update": "2024-11-07T17:30:00Z",
      "indicators_count": 85000,
      "reliability_score": 0.93
    }
  ]
}
```

---

### GET /sources/{source_id}/stream

Stream newly added indicators from a specific source (NDJSON format).

**Method**: `GET`
**Endpoint**: `/api/v1/sources/{source_id}/stream`
**Authentication**: Optional

**Path Parameters**:

| Name | Type | Description |
|------|------|-------------|
| source_id | string | Source ID |

**Request**:
```bash
curl -X GET http://localhost:8006/api/v1/sources/src-001/stream \
  --stream
```

**Response (200 OK) - Streaming NDJSON**:
```
{"value":"8.8.8.8","type":"ipv4","threat":"spam","timestamp":"2024-11-07T18:00:00Z"}
{"value":"malware-domain.com","type":"domain","threat":"malware","timestamp":"2024-11-07T18:00:01Z"}
{"value":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","type":"sha256","threat":"malware","timestamp":"2024-11-07T18:00:02Z"}
```

---

## Telemetry

### POST /telemetry/events

Ingest telemetry events from sensors and endpoints.

**Method**: `POST`
**Endpoint**: `/api/v1/telemetry/events`
**Authentication**: Optional

**Request Body**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| events | array | Yes | Array of telemetry events |
| events[].type | string | Yes | Event type: network_connection, file_operation, process_execution, dns_query |
| events[].sensor_id | string | Yes | Sensor/endpoint identifier |
| events[].timestamp | string | Yes | ISO-8601 timestamp |
| events[].data | object | Yes | Event-specific data |

**Request**:
```bash
curl -X POST http://localhost:8006/api/v1/telemetry/events \
  -H "Content-Type: application/json" \
  -d '{
    "events": [
      {
        "type": "network_connection",
        "sensor_id": "sensor-001",
        "timestamp": "2024-11-07T18:00:00Z",
        "data": {
          "source_ip": "192.168.1.100",
          "destination_ip": "8.8.8.8",
          "destination_port": 53,
          "protocol": "udp"
        }
      }
    ]
  }'
```

**Response (202 Accepted)**:
```json
{
  "ingested": 1,
  "errors": 0,
  "message": "Events queued for processing"
}
```

---

### GET /telemetry/statistics

Get aggregated telemetry statistics and metrics.

**Method**: `GET`
**Endpoint**: `/api/v1/telemetry/statistics`
**Authentication**: Optional

**Query Parameters**:

| Name | Type | Description |
|------|------|-------------|
| time_range | string | 1h, 24h, 7d, 30d (default: 24h) |
| sensor_id | string | Filter by specific sensor |

**Request**:
```bash
curl -X GET "http://localhost:8006/api/v1/telemetry/statistics?time_range=24h"
```

**Response (200 OK)**:
```json
{
  "total_events": 45000,
  "events_by_type": {
    "network_connection": 30000,
    "dns_query": 10000,
    "file_operation": 4000,
    "process_execution": 1000
  },
  "active_sensors": 15,
  "events_per_sensor": 3000,
  "suspicious_events": 45
}
```

---

## Error Codes

| Code | Status | Description |
|------|--------|-------------|
| 200 | OK | Request successful |
| 202 | Accepted | Data successfully ingested (async processing) |
| 400 | Bad Request | Invalid query parameters or request body |
| 401 | Unauthorized | Invalid API key (if provided) |
| 404 | Not Found | Requested indicator or resource not found |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server error (contact support) |

---

## Rate Limiting

The Data Service enforces rate limits based on authentication:

- **Anonymous requests**: 100 requests/minute
- **Authenticated requests (API Key)**: 1,000 requests/minute

Rate limit information is returned in response headers:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1730963100
```

---

## Examples

### Search for Malicious Domains

```bash
# Search for domains with high threat level
curl -X GET "http://localhost:8006/api/v1/indicators/search?type=domain&threat_level=malware&severity=critical" \
  -H "X-API-Key: your-api-key"
```

### Bulk Check IP Addresses

```bash
#!/bin/bash

IPS=("8.8.8.8" "1.1.1.1" "192.168.1.1" "10.0.0.1")

curl -X POST http://localhost:8006/api/v1/indicators/bulk-lookup \
  -H "Content-Type: application/json" \
  -d "{
    \"indicators\": $(echo "${IPS[@]}" | jq -R -s -c 'split(" ")')
  }" | jq '.results[] | select(.threat_level != "benign")'
```

### Real-time Threat Feed Integration

```bash
# Stream malware indicators from Abuse.ch
curl -X GET http://localhost:8006/api/v1/sources/abuse-ch/stream \
  --stream | while IFS= read -r line; do
  THREAT=$(echo "$line" | jq -r '.threat')
  VALUE=$(echo "$line" | jq -r '.value')

  if [ "$THREAT" = "malware" ]; then
    echo "New malware detected: $VALUE"
    # Send to alerting system
  fi
done
```

---

## Related Documentation

- [Security Policy](../../security/policy.md) - Authentication requirements
- [API Reference Hub](../api-reference.html) - All service endpoints
- [Guardian Service API](../guardian/endpoints.md) - Vulnerability management
- [Agents Service API](../agents/endpoints.md) - Threat analysis

---

**Last Updated**: November 7, 2024
**API Version**: v1
**Status**: Stable
**Base Port**: 8006
