# Data Service API

> **Hand-written reference.** This page was written in November 2024 and
> has not been re-checked endpoint by endpoint against the code since.
> Paths, fields and examples may have drifted; the service's own OpenAPI
> document is authoritative. Corrections are welcome as issues or pull
> requests.
>
> All IDs, keys (such as `your-api-key`) and host names in the examples are
> fictitious placeholders.

**Gateway path**: `https://<host>/api/v1/data/...` (proxied to the service's `/api/v1/...`)  
**Local port**: listed in [Service ports](../../guides/ports.md); the examples below call the service directly on `localhost`  
**Authentication**: Optional (API Key for enhanced features)

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
curl -X GET "http://localhost:8002/api/v1/indicators/search" \
  -H "X-API-Key: your-api-key"
```

### No Authentication Required

Public endpoints work without authentication:

```bash
curl -X GET "http://localhost:8002/api/v1/indicators/search?q=example.com"
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
| ------ | ------ | ---------- | --------- | ------------- |
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
curl -X GET "http://localhost:8002/api/v1/indicators/search?q=malicious-domain.com&limit=20" \
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
curl -X POST http://localhost:8002/api/v1/indicators/bulk-lookup \
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
curl -X GET http://localhost:8002/api/v1/intelligence/ip/192.168.1.100
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
curl -X GET http://localhost:8002/api/v1/intelligence/domain/example.com
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
curl -X GET http://localhost:8002/api/v1/intelligence/hash/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
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
curl -X GET http://localhost:8002/api/v1/sources?limit=20
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
curl -X GET http://localhost:8002/api/v1/sources/src-001/stream \
  --stream
```

**Response (200 OK) - Streaming NDJSON**:

```json
{"value":"8.8.8.8","type":"ipv4","threat":"spam","timestamp":"2024-11-07T18:00:00Z"}
{"value":"malware-domain.com","type":"domain","threat":"malware","timestamp":"2024-11-07T18:00:01Z"}
{"value":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","type":"sha256","threat":"malware","timestamp":"2024-11-07T18:00:02Z"}
```

---

## Telemetry

Sensor telemetry belongs to a team: the team of the API key the sensor sends
it with. Every route below is reached through the gateway, at
`https://<gateway>/api/v1/data/...`, and reads or writes the caller's team's
telemetry only. The data service itself accepts only requests the gateway has
authenticated.

### POST /ingest

Store a batch of telemetry events. The sensor's forwarder calls it; see the
sensor README, "Sending telemetry to Wildbox".

**Method**: `POST`
**Endpoint**: `/api/v1/data/ingest` (gateway), `/api/v1/ingest` (data service)
**Authentication**: an identity API key in `X-API-Key` with the `data:ingest`
scope (or `write`, `data:write`), or a session. The events are stored under
the caller's team; a team named in the body is ignored.

**Request Body**:

| Field | Type | Required | Description |
| ------- | ------ | ---------- | ------------- |
| batch_id | string | No | Identifies the batch; generated when absent |
| events | array | Yes | Up to 1000 events (`MAX_BATCH_SIZE`) |
| events[].sensor_id | string | Yes | The sensor's name, unique within the team |
| events[].event_type | string | Yes | `process_event`, `network_connection`, `file_change`, `user_event`, `system_inventory`, `authentication` or `security_event` |
| events[].timestamp | string | Yes | ISO-8601 time of the event |
| events[].event_data | object | Yes | Event-specific data |
| events[].source_host | string | No | Host the event comes from |
| events[].raw_data | string | No | The raw record |
| events[].severity | integer | No | 1 to 10, default 1 |
| events[].tags | array | No | Strings |

**Request**:

```bash
curl --cacert open-security-gateway/ssl/wildbox.crt \
  -X POST https://localhost/api/v1/data/ingest \
  -H "X-API-Key: $SENSOR_DATA_LAKE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "events": [
      {
        "sensor_id": "sensor-001",
        "event_type": "network_connection",
        "timestamp": "2024-11-07T18:00:00Z",
        "source_host": "web-1",
        "event_data": {"remote_address": "8.8.8.8", "remote_port": 53},
        "tags": ["network.process_connections"]
      }
    ]
  }'
```

**Response (200 OK)**:

```json
{
  "batch_id": "0b6b2c9e-5d0f-4a51-9c3e-2b1f7a8d9e10",
  "events_received": 1,
  "events_ingested": 1,
  "errors": [],
  "ingested_at": "2024-11-07T18:00:01Z"
}
```

401 from the gateway: the key is invalid, expired or revoked. 403
`insufficient_scope`: the key lacks `data:ingest`. 400: more events than
`MAX_BATCH_SIZE`. 503: the batch was not stored; send it again.

---

### GET /telemetry/events

The caller's team's events, most recent first.

**Endpoint**: `/api/v1/data/telemetry/events` (gateway)

**Query Parameters**: `sensor_id`, `event_type`, `start_time`, `end_time`
(ISO-8601), `limit` (up to 1000, default 100), `offset`.

```bash
curl --cacert open-security-gateway/ssl/wildbox.crt -H "X-API-Key: $KEY" \
  "https://localhost/api/v1/data/telemetry/events?sensor_id=sensor-001&limit=10"
```

### GET /telemetry/stats

Counts over the caller's team's events in the last `hours` (default 24):
`total_events`, `active_sensors`, `events_by_type`. `sensor_id` narrows them
to one sensor.

```bash
curl --cacert open-security-gateway/ssl/wildbox.crt -H "X-API-Key: $KEY" \
  "https://localhost/api/v1/data/telemetry/stats?hours=24"
```

### GET /sensors and GET /sensors/{sensor_id}

The caller's team's sensors (`active_only`, default true), and one of them by
its ID; another team's sensor answers 404.

---

## Error Codes

| Code | Status | Description |
| ------ | -------- | ------------- |
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

```yaml
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1730963100
```

---

## Examples

### Search for Malicious Domains

```bash
# Search for domains with high threat level
curl -X GET "http://localhost:8002/api/v1/indicators/search?type=domain&threat_level=malware&severity=critical" \
  -H "X-API-Key: your-api-key"
```

### Bulk Check IP Addresses

```bash
#!/bin/bash

IPS=("8.8.8.8" "1.1.1.1" "192.168.1.1" "10.0.0.1")

curl -X POST http://localhost:8002/api/v1/indicators/bulk-lookup \
  -H "Content-Type: application/json" \
  -d "{
    \"indicators\": $(echo "${IPS[@]}" | jq -R -s -c 'split(" ")')
  }" | jq '.results[] | select(.threat_level != "benign")'
```

### Real-time Threat Feed Integration

```bash
# Stream malware indicators from Abuse.ch
curl -X GET http://localhost:8002/api/v1/sources/abuse-ch/stream \
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
- [API Reference Hub](../../api-reference.html) - All service endpoints
- [Guardian Service API](../guardian/endpoints.md) - Vulnerability management
- [Agents Service API](../agents/endpoints.md) - Threat analysis

