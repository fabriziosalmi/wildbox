# Agents Service API

**Service Port**: 8004
**Base URL**: `http://localhost:8004`
**Authentication**: Bearer Token (JWT) required for analysis endpoints
**Documentation**: [Live Swagger UI](http://localhost:8004/docs) | [OpenAPI Schema](http://localhost:8004/openapi.json)

---

## Overview

The Agents Service is an AI-powered threat intelligence and enrichment platform that uses large language models and security tools to analyze indicators of compromise (IOCs) and provide comprehensive threat assessments. It orchestrates multiple security analysis tools through intelligent agents to correlate findings and generate actionable intelligence.

## Table of Contents

- [Authentication](#authentication)
- [Health & Monitoring](#health--monitoring)
- [Threat Analysis](#threat-analysis)
- [Error Codes](#error-codes)
- [Rate Limiting](#rate-limiting)

---

## Authentication

### Bearer Token Authentication

The analysis endpoints require JWT Bearer token authentication:

```bash
curl -X POST http://localhost:8004/v1/analyze \
  -H "Authorization: Bearer your-jwt-token-here" \
  -H "Content-Type: application/json" \
  -d '{...}'
```

### Internal Service Authentication

Inter-service calls use the `X-API-Key` header:

```bash
curl -X GET http://localhost:8004/health \
  -H "X-API-Key: wildbox-internal-key"
```

---

## Health & Monitoring

### GET /

Service information and root endpoint.

**Method**: `GET`
**Endpoint**: `/`
**Authentication**: Not required

**Request**:
```bash
curl http://localhost:8004/
```

**Response (200 OK)**:
```json
{
  "service": "Wildbox Agents Service",
  "version": "1.0.0",
  "status": "operational",
  "port": 8004
}
```

---

### GET /health

Health check endpoint for service monitoring and orchestration.

**Method**: `GET`
**Endpoint**: `/health`
**Authentication**: Not required

**Request**:
```bash
curl http://localhost:8004/health
```

**Response (200 OK)**:
```json
{
  "status": "healthy",
  "timestamp": "2024-11-07T18:30:00Z",
  "version": "1.0.0",
  "services": {
    "redis": "healthy",
    "celery": "healthy",
    "openai": "configured"
  }
}
```

---

### GET /stats

Service statistics and performance metrics.

**Method**: `GET`
**Endpoint**: `/stats`
**Authentication**: Not required

**Request**:
```bash
curl http://localhost:8004/stats
```

**Response (200 OK)**:
```json
{
  "total_analyses": 450,
  "pending_tasks": 3,
  "running_tasks": 2,
  "completed_today": 87,
  "failed_today": 2,
  "average_duration_seconds": 32.5,
  "uptime_seconds": 86400,
  "success_rate": 0.977
}
```

---

## Threat Analysis

### POST /v1/analyze

Submit an indicator of compromise (IOC) for AI-powered threat analysis.

**Method**: `POST`
**Endpoint**: `/v1/analyze`
**Authentication**: Required (Bearer Token)
**Rate Limit**: 100 requests/minute per token

**Request Body**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| ioc | object | Yes | Indicator of compromise object |
| ioc.type | string | Yes | IOC type: ipv4, ipv6, domain, url, md5, sha1, sha256, email |
| ioc.value | string | Yes | IOC value (IP address, domain name, URL, or hash) |
| priority | string | No | Analysis priority: low, normal, high (default: normal) |

**Supported IOC Types**:
- `ipv4` - IPv4 address (e.g., 192.168.1.1)
- `ipv6` - IPv6 address (e.g., 2001:4860:4860::8888)
- `domain` - Domain name (e.g., example.com)
- `url` - Full URL (e.g., https://example.com/path)
- `md5` - MD5 file hash
- `sha1` - SHA1 file hash
- `sha256` - SHA256 file hash
- `email` - Email address (e.g., user@example.com)

**Request**:
```bash
curl -X POST http://localhost:8004/v1/analyze \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{
    "ioc": {
      "type": "ipv4",
      "value": "8.8.8.8"
    },
    "priority": "high"
  }'
```

**Response (202 Accepted)**:
```json
{
  "task_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "pending",
  "created_at": "2024-11-07T18:35:00Z",
  "started_at": null,
  "completed_at": null,
  "progress": "Queued for analysis",
  "error": null,
  "result_url": "/v1/analyze/550e8400-e29b-41d4-a716-446655440000"
}
```

**Error (401 Unauthorized)**:
```json
{
  "error": "Unauthorized",
  "message": "Invalid or missing authorization token",
  "status": "error"
}
```

---

### GET /v1/analyze/{task_id}

Retrieve the status and results of a submitted analysis task.

**Method**: `GET`
**Endpoint**: `/v1/analyze/{task_id}`
**Authentication**: Not required (status can be checked by task ID)

**Path Parameters**:

| Name | Type | Description |
|------|------|-------------|
| task_id | string | UUID of the analysis task |

**Request**:
```bash
curl -X GET http://localhost:8004/v1/analyze/550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer your-jwt-token"
```

**Response (200 OK) - Pending**:
```json
{
  "task_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "created_at": "2024-11-07T18:35:00Z",
  "started_at": "2024-11-07T18:35:02Z",
  "completed_at": null,
  "progress": "Executing reputation check...",
  "error": null,
  "result_url": "/v1/analyze/550e8400-e29b-41d4-a716-446655440000"
}
```

**Response (200 OK) - Completed**:
```json
{
  "task_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "created_at": "2024-11-07T18:35:00Z",
  "started_at": "2024-11-07T18:35:02Z",
  "completed_at": "2024-11-07T18:35:35Z",
  "ioc": {
    "type": "ipv4",
    "value": "8.8.8.8"
  },
  "verdict": "Benign",
  "confidence": 0.98,
  "executive_summary": "Google Public DNS server. Widely used and trusted service. No malicious activity detected.",
  "evidence": [
    {
      "source": "reputation_check",
      "finding": "Known benign service - Google DNS",
      "severity": "info",
      "data": {
        "reputation_score": 95,
        "sources_count": 45
      }
    },
    {
      "source": "geolocation",
      "finding": "Located in United States (AS15169 - Google)",
      "severity": "info",
      "data": {
        "country": "US",
        "asn": "AS15169",
        "organization": "Google LLC"
      }
    }
  ],
  "recommended_actions": [
    "Whitelist this service",
    "Monitor for abuse from this IP"
  ],
  "full_report": "# Threat Analysis Report\n\n## IOC: 8.8.8.8\n\n### Verdict: Benign\n...",
  "tools_used": [
    "reputation_check_tool",
    "geolocation_lookup_tool",
    "whois_lookup_tool",
    "dns_lookup_tool"
  ],
  "analysis_duration_seconds": 33.2
}
```

**Response (404 Not Found)**:
```json
{
  "error": "Not Found",
  "message": "Task ID not found or expired",
  "status": "error"
}
```

**Task Status Values**:
- `pending` - Task queued, waiting to start
- `running` - Task currently executing
- `completed` - Task finished successfully
- `failed` - Task encountered an error
- `revoked` - Task was cancelled

---

### DELETE /v1/analyze/{task_id}

Cancel a pending or running analysis task.

**Method**: `DELETE`
**Endpoint**: `/v1/analyze/{task_id}`
**Authentication**: Not required

**Path Parameters**:

| Name | Type | Description |
|------|------|-------------|
| task_id | string | UUID of the analysis task to cancel |

**Request**:
```bash
curl -X DELETE http://localhost:8004/v1/analyze/550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer your-jwt-token"
```

**Response (200 OK)**:
```json
{
  "message": "Task cancelled successfully",
  "task_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "revoked"
}
```

**Response (404 Not Found)**:
```json
{
  "error": "Not Found",
  "message": "Task ID not found or already completed",
  "status": "error"
}
```

---

## Analysis Tools

The Agents Service has access to 9 security analysis tools that are automatically selected and executed based on the IOC type:

| Tool | Purpose | IOC Types |
|------|---------|-----------|
| **reputation_check_tool** | Multi-source threat reputation scoring | IPv4, IPv6, Domain, URL, Hash, Email |
| **whois_lookup_tool** | Domain/IP registration information | Domain, IPv4, IPv6 |
| **dns_lookup_tool** | DNS record resolution and history | Domain |
| **port_scan_tool** | Network service discovery | IPv4, IPv6 |
| **url_analysis_tool** | URL behavior and content analysis | URL |
| **hash_lookup_tool** | File hash reputation (VirusTotal, AlienVault) | MD5, SHA1, SHA256 |
| **geolocation_lookup_tool** | IP geolocation and ASN information | IPv4, IPv6 |
| **threat_intel_query_tool** | Internal threat data lake search | All types |
| **vulnerability_search_tool** | CVE and vulnerability lookup | All types |

---

## Error Codes

| Code | Status | Description |
|------|--------|-------------|
| 202 | Accepted | Analysis task successfully submitted |
| 400 | Bad Request | Invalid IOC type or value format |
| 401 | Unauthorized | Missing or invalid authorization token |
| 404 | Not Found | Task ID not found or expired |
| 500 | Internal Server Error | Service or dependency error |
| 503 | Service Unavailable | Service temporarily unavailable |

---

## Rate Limiting

The Agents Service enforces rate limits on analysis requests:

- **Analysis endpoint**: 100 requests/minute per authenticated token
- **Health/stats endpoints**: 1,000 requests/minute

Rate limit information is returned in response headers:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1730963100
```

When rate limit is exceeded (429 error):
```json
{
  "error": "Too Many Requests",
  "message": "Rate limit exceeded. Try again after 60 seconds",
  "status": "error"
}
```

---

## Task Timeouts

- **Maximum analysis time**: 10 minutes (600 seconds)
- **Maximum concurrent tasks**: 5 per service
- **Result storage**: Results expire after 1 hour
- **Max agent iterations**: 15 (prevents infinite loops)

---

## Examples

### Complete Threat Analysis Workflow

```bash
# 1. Submit IOC for analysis
TASK_ID=$(curl -s -X POST http://localhost:8004/v1/analyze \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{
    "ioc": {
      "type": "domain",
      "value": "suspicious-domain.com"
    },
    "priority": "high"
  }' | jq -r '.task_id')

echo "Analysis task submitted: $TASK_ID"

# 2. Poll for analysis results
while true; do
  RESULT=$(curl -s -X GET http://localhost:8004/v1/analyze/$TASK_ID \
    -H "Authorization: Bearer your-jwt-token")

  STATUS=$(echo $RESULT | jq -r '.status')

  if [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ]; then
    echo "Analysis complete!"
    echo $RESULT | jq '.'
    break
  fi

  PROGRESS=$(echo $RESULT | jq -r '.progress')
  echo "Status: $PROGRESS"

  sleep 2
done

# 3. Extract verdict and recommendations
echo "Verdict:"
echo $RESULT | jq '.verdict'
echo "Confidence:"
echo $RESULT | jq '.confidence'
echo "Recommended Actions:"
echo $RESULT | jq '.recommended_actions[]'
```

### Analyze Multiple IOCs in Batch

```bash
#!/bin/bash

IOCS=("8.8.8.8" "example.com" "192.168.1.1")
TOKEN="your-jwt-token"

for ioc in "${IOCS[@]}"; do
  echo "Analyzing: $ioc"

  TASK_ID=$(curl -s -X POST http://localhost:8004/v1/analyze \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "ioc": {
        "type": "ipv4",
        "value": "'$ioc'"
      },
      "priority": "normal"
    }' | jq -r '.task_id')

  echo "Task ID: $TASK_ID"
  sleep 1
done
```

### Integration with Guardian Service

```bash
# Get IOCs from Guardian vulnerabilities
VULNERABLE_IPS=$(curl -s http://localhost:8001/api/v1/vulnerabilities/?severity=critical \
  -H "X-API-Key: api-key" | jq -r '.results[].affected_assets[].ip_address')

# Analyze each with Agents Service
for ip in $VULNERABLE_IPS; do
  echo "Analyzing $ip with Agents Service"

  TASK_ID=$(curl -s -X POST http://localhost:8004/v1/analyze \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
      \"ioc\": {
        \"type\": \"ipv4\",
        \"value\": \"$ip\"
      },
      \"priority\": \"high\"
    }" | jq -r '.task_id')

  echo "Queued analysis for $ip: $TASK_ID"
done
```

---

## Related Documentation

- [Security Policy](../../security/policy.md) - Authentication requirements
- [API Reference Hub](../api-reference.html) - All service endpoints
- [Quickstart Guide](../../guides/quickstart.md) - Getting started with APIs
- [Guardian Service API](../guardian/endpoints.md) - Asset and vulnerability management
- [Data Service API](../data/endpoints.md) - Threat intelligence data

---

**Last Updated**: November 7, 2024
**API Version**: v1
**Status**: Stable
**Base Port**: 8004
