# Tools Service API

**Service Port**: 8013
**Base URL**: `http://localhost:8013/api`
**Authentication**: API Key (X-API-Key header) required
**Documentation**: [Live Swagger UI](http://localhost:8013/docs) | [OpenAPI Schema](http://localhost:8013/openapi.json)

---

## Overview

The Tools Service provides a unified interface for executing 54+ security analysis tools across multiple categories including vulnerability scanning, network analysis, web application testing, and threat intelligence. It manages tool execution, monitors task status, and aggregates results from diverse security tools.

## Table of Contents

- [Authentication](#authentication)
- [Tool Management](#tool-management)
- [Tool Execution](#tool-execution)
- [System Monitoring](#system-monitoring)
- [Error Codes](#error-codes)
- [Rate Limiting](#rate-limiting)

---

## Authentication

All Tools Service endpoints require API Key authentication:

```bash
curl -X GET http://localhost:8013/api/tools \
  -H "X-API-Key: your-api-key"
```

---

## Tool Management

### GET /tools

List all available security tools.

**Method**: `GET`
**Endpoint**: `/tools`
**Authentication**: Required (API Key)
**Rate Limit**: 100 requests/minute

**Query Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| category | string | No | Filter by category: scanner, analyzer, enricher, responder |
| status | string | No | Filter by status: active, inactive, error |
| limit | integer | No | Number of results (default: 50) |
| offset | integer | No | Pagination offset |

**Request**:
```bash
curl -X GET "http://localhost:8013/api/tools?category=scanner&status=active" \
  -H "X-API-Key: your-api-key"
```

**Response (200 OK)**:
```json
{
  "count": 54,
  "results": [
    {
      "id": "nessus-001",
      "name": "Nessus Scanner",
      "category": "scanner",
      "vendor": "Tenable",
      "version": "10.4.2",
      "status": "active",
      "supports_async": true,
      "execution_timeout_seconds": 3600,
      "description": "Comprehensive vulnerability scanner",
      "capabilities": [
        "vulnerability_scan",
        "compliance_check",
        "asset_discovery"
      ]
    },
    {
      "id": "burpsuite-001",
      "name": "Burp Suite Professional",
      "category": "scanner",
      "vendor": "PortSwigger",
      "version": "2024.2.1",
      "status": "active",
      "supports_async": true,
      "execution_timeout_seconds": 1800,
      "description": "Web application security testing tool",
      "capabilities": [
        "web_app_scan",
        "api_scan",
        "dast"
      ]
    }
  ]
}
```

---

### GET /tools/{tool_id}/info

Get detailed information about a specific tool.

**Method**: `GET`
**Endpoint**: `/tools/{tool_id}/info`
**Authentication**: Required (API Key)

**Path Parameters**:

| Name | Type | Description |
|------|------|-------------|
| tool_id | string | Tool identifier |

**Request**:
```bash
curl -X GET http://localhost:8013/api/tools/nessus-001/info \
  -H "X-API-Key: your-api-key"
```

**Response (200 OK)**:
```json
{
  "id": "nessus-001",
  "name": "Nessus Scanner",
  "category": "scanner",
  "vendor": "Tenable",
  "version": "10.4.2",
  "status": "active",
  "description": "Comprehensive vulnerability scanner with multiple scan profiles",
  "documentation_url": "https://docs.tenable.com/nessus",
  "supports_async": true,
  "execution_timeout_seconds": 3600,
  "supports_scheduling": true,
  "supports_parallelization": true,
  "input_parameters": [
    {
      "name": "target",
      "type": "string",
      "required": true,
      "description": "Target IP, CIDR, or hostname"
    },
    {
      "name": "scan_profile",
      "type": "string",
      "required": false,
      "default": "basic",
      "enum": ["basic", "full", "compliance", "discovery"],
      "description": "Scan profile to use"
    },
    {
      "name": "credentials",
      "type": "object",
      "required": false,
      "description": "Optional authentication credentials"
    }
  ],
  "output_format": "json",
  "estimated_execution_time_minutes": 45,
  "requires_license": true,
  "license_status": "active",
  "license_expires": "2024-12-31T23:59:59Z"
}
```

---

## Tool Execution

### POST /tools/{tool_id}/execute

Execute a security tool with specified parameters.

**Method**: `POST`
**Endpoint**: `/tools/{tool_id}/execute`
**Authentication**: Required (API Key)

**Path Parameters**:

| Name | Type | Description |
|------|------|-------------|
| tool_id | string | Tool identifier |

**Request Body**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| parameters | object | Yes | Tool-specific parameters |
| async_mode | boolean | No | Execute asynchronously (default: true) |
| callback_url | string | No | Webhook URL for async completion |
| priority | string | No | Execution priority: low, normal, high |
| tags | array | No | Tags for organizing execution |

**Request**:
```bash
curl -X POST http://localhost:8013/api/tools/nessus-001/execute \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "parameters": {
      "target": "192.168.1.0/24",
      "scan_profile": "full"
    },
    "async_mode": true,
    "priority": "high"
  }'
```

**Response (202 Accepted)**:
```json
{
  "execution_id": "exec-550e8400-e29b-41d4-a716-446655440000",
  "tool_id": "nessus-001",
  "status": "queued",
  "created_at": "2024-11-07T18:35:00Z",
  "started_at": null,
  "estimated_completion": "2024-11-07T19:35:00Z",
  "result_url": "/tools/nessus-001/executions/exec-550e8400-e29b-41d4-a716-446655440000"
}
```

---

### GET /tools/{tool_id}/executions/{execution_id}

Get the status and results of a tool execution.

**Method**: `GET`
**Endpoint**: `/tools/{tool_id}/executions/{execution_id}`
**Authentication**: Required (API Key)

**Path Parameters**:

| Name | Type | Description |
|------|------|-------------|
| tool_id | string | Tool identifier |
| execution_id | string | Execution ID |

**Request**:
```bash
curl -X GET http://localhost:8013/api/tools/nessus-001/executions/exec-550e8400-e29b-41d4-a716-446655440000 \
  -H "X-API-Key: your-api-key"
```

**Response (200 OK) - Running**:
```json
{
  "execution_id": "exec-550e8400-e29b-41d4-a716-446655440000",
  "tool_id": "nessus-001",
  "status": "running",
  "created_at": "2024-11-07T18:35:00Z",
  "started_at": "2024-11-07T18:35:05Z",
  "progress_percent": 35,
  "progress_message": "Scanning 192.168.1.50/32... (35% complete)",
  "estimated_completion": "2024-11-07T19:35:00Z"
}
```

**Response (200 OK) - Completed**:
```json
{
  "execution_id": "exec-550e8400-e29b-41d4-a716-446655440000",
  "tool_id": "nessus-001",
  "status": "completed",
  "created_at": "2024-11-07T18:35:00Z",
  "started_at": "2024-11-07T18:35:05Z",
  "completed_at": "2024-11-07T19:35:22Z",
  "execution_time_seconds": 3617,
  "results": {
    "vulnerabilities_found": 45,
    "critical": 3,
    "high": 12,
    "medium": 30,
    "hosts_scanned": 256,
    "services_discovered": 1250,
    "compliance_issues": 8,
    "assets_discovered": 156
  },
  "report_url": "/tools/nessus-001/executions/exec-550e8400-e29b-41d4-a716-446655440000/report",
  "raw_output_url": "/tools/nessus-001/executions/exec-550e8400-e29b-41d4-a716-446655440000/raw"
}
```

---

### DELETE /tools/{tool_id}/executions/{execution_id}

Cancel a running or pending tool execution.

**Method**: `DELETE`
**Endpoint**: `/tools/{tool_id}/executions/{execution_id}`
**Authentication**: Required (API Key)

**Request**:
```bash
curl -X DELETE http://localhost:8013/api/tools/nessus-001/executions/exec-550e8400-e29b-41d4-a716-446655440000 \
  -H "X-API-Key: your-api-key"
```

**Response (200 OK)**:
```json
{
  "message": "Execution cancelled successfully",
  "execution_id": "exec-550e8400-e29b-41d4-a716-446655440000",
  "status": "cancelled"
}
```

---

## System Monitoring

### GET /health

Service health check.

**Method**: `GET`
**Endpoint**: `/health`
**Authentication**: Not required

**Request**:
```bash
curl http://localhost:8013/api/health
```

**Response (200 OK)**:
```json
{
  "status": "healthy",
  "timestamp": "2024-11-07T18:40:00Z",
  "version": "1.0.0",
  "services": {
    "database": "healthy",
    "queue": "healthy",
    "tools": [
      {
        "tool_id": "nessus-001",
        "status": "healthy",
        "last_check": "2024-11-07T18:39:30Z"
      }
    ]
  }
}
```

---

### GET /system/info

Get system and service information.

**Method**: `GET`
**Endpoint**: `/system/info`
**Authentication**: Required (API Key)

**Request**:
```bash
curl -X GET http://localhost:8013/api/system/info \
  -H "X-API-Key: your-api-key"
```

**Response (200 OK)**:
```json
{
  "service": "Wildbox Tools Service",
  "version": "1.0.0",
  "uptime_seconds": 604800,
  "tools_available": 54,
  "tools_active": 52,
  "tools_inactive": 2,
  "total_executions": 1500,
  "active_executions": 3,
  "database_size_gb": 25.5,
  "storage_available_gb": 450
}
```

---

### GET /system/metrics

Get detailed performance metrics.

**Method**: `GET`
**Endpoint**: `/system/metrics`
**Authentication**: Required (API Key)

**Query Parameters**:

| Name | Type | Description |
|------|------|-------------|
| time_range | string | 1h, 24h, 7d, 30d (default: 24h) |

**Request**:
```bash
curl -X GET "http://localhost:8013/api/system/metrics?time_range=24h" \
  -H "X-API-Key: your-api-key"
```

**Response (200 OK)**:
```json
{
  "time_range": "24h",
  "total_executions": 156,
  "successful_executions": 150,
  "failed_executions": 6,
  "average_execution_time_seconds": 245,
  "executions_by_tool": {
    "nessus-001": 45,
    "burpsuite-001": 38,
    "metasploit-001": 22,
    "qualys-001": 51
  },
  "executions_by_status": {
    "completed": 150,
    "failed": 6,
    "cancelled": 0
  },
  "cpu_average_percent": 45.2,
  "memory_average_percent": 62.3,
  "disk_io_average_mbps": 12.5
}
```

---

## Available Tools by Category

### Vulnerability Scanners (15 tools)
Nessus, Qualys, OpenVAS, Rapid7 Nexpose, Acunetix, AppScan, Checkmarx, Fortify, Veracode, etc.

### Network Analysis (12 tools)
Wireshark, tcpdump, nmap, Zeek, Suricata, Security Onion, etc.

### Web Application Testing (10 tools)
Burp Suite, OWASP ZAP, Acunetix, Rapid7, AppScan, WebInspect, etc.

### Threat Intelligence (8 tools)
Shodan, GreyNoise, Censys, AlienVault OTX, Recorded Future, etc.

### Malware Analysis (6 tools)
Cuckoo Sandbox, ANY.RUN, Joe Sandbox, Intezer, VirusTotal API, etc.

### Configuration Management (3 tools)
Lynis, OpenSCAP, Compliance Checker

---

## Error Codes

| Code | Status | Description |
|------|--------|-------------|
| 200 | OK | Request successful |
| 202 | Accepted | Tool execution submitted asynchronously |
| 400 | Bad Request | Invalid parameters or request body |
| 401 | Unauthorized | Missing or invalid API key |
| 404 | Not Found | Tool or execution not found |
| 409 | Conflict | Tool not available or in error state |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Service error |

---

## Rate Limiting

The Tools Service enforces rate limits per API key:

- **Standard API Keys**: 100 requests/minute
- **Premium API Keys**: 1,000 requests/minute

Rate limit information is returned in response headers:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1730963100
```

---

## Examples

### Execute a Network Vulnerability Scan

```bash
# Get Nessus scanner info
curl -X GET http://localhost:8013/api/tools/nessus-001/info \
  -H "X-API-Key: your-api-key" | jq '.'

# Execute full vulnerability scan
EXEC_ID=$(curl -s -X POST http://localhost:8013/api/tools/nessus-001/execute \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "parameters": {
      "target": "192.168.0.0/16",
      "scan_profile": "full"
    },
    "async_mode": true,
    "priority": "high"
  }' | jq -r '.execution_id')

echo "Execution started: $EXEC_ID"

# Monitor progress
while true; do
  STATUS=$(curl -s -X GET "http://localhost:8013/api/tools/nessus-001/executions/$EXEC_ID" \
    -H "X-API-Key: your-api-key" | jq '.')

  STATE=$(echo "$STATUS" | jq -r '.status')
  PROGRESS=$(echo "$STATUS" | jq -r '.progress_percent // "N/A"')

  echo "Status: $STATE - Progress: $PROGRESS%"

  if [ "$STATE" = "completed" ] || [ "$STATE" = "failed" ]; then
    echo "$STATUS" | jq '.results'
    break
  fi

  sleep 5
done
```

### Execute Multiple Tools in Sequence

```bash
#!/bin/bash

TOOLS=("nessus-001" "burpsuite-001" "metasploit-001")
TARGET="192.168.1.1"

for tool in "${TOOLS[@]}"; do
  echo "Executing $tool on $TARGET"

  EXEC=$(curl -s -X POST "http://localhost:8013/api/tools/$tool/execute" \
    -H "X-API-Key: your-api-key" \
    -H "Content-Type: application/json" \
    -d "{
      \"parameters\": {
        \"target\": \"$TARGET\"
      },
      \"async_mode\": true
    }")

  EXEC_ID=$(echo "$EXEC" | jq -r '.execution_id')
  echo "Execution ID: $EXEC_ID"

  sleep 2
done
```

---

## Related Documentation

- [Security Policy](../../security/policy.md) - Authentication requirements
- [API Reference Hub](../api-reference.html) - All service endpoints
- [Guardian Service API](../guardian/endpoints.md) - Asset management
- [Responder Service API](../responder/endpoints.md) - Incident response

---

**Last Updated**: November 7, 2024
**API Version**: v1
**Status**: Stable
**Base Port**: 8013
