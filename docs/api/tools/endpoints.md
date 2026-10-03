# Tools Service API

> **Hand-written reference.** This page was written in November 2024 and
> has not been re-checked endpoint by endpoint against the code since.
> Paths, fields and examples may have drifted; the service's own OpenAPI
> document is authoritative. Corrections are welcome as issues or pull
> requests.
>
> All IDs, keys (such as `your-api-key`) and host names in the examples are
> fictitious placeholders.

**Gateway path**: `https://<host>/api/v1/tools/...` (proxied to the service's `/api/tools/...`)  
**Local port**: listed in [Service ports](../../guides/ports.md); the service accepts only requests forwarded by the gateway, so the tool examples below call the gateway  
**Authentication**: through the gateway only (JWT, or a personal API key sent to the gateway as `X-API-Key`)

---

## Overview

The Tools Service provides a unified interface for executing 52 security analysis tools (the directories under `open-security-tools/app/tools` whose `main.py` defines `execute_tool`, which is what `app/tool_loader.py` loads; counted on 2 October 2026) across multiple categories including vulnerability scanning, network analysis, web application testing, and threat intelligence. It manages tool execution, monitors task status, and aggregates results from diverse security tools.

### TLS Certificate Verification

Tools that connect over HTTPS verify the certificate chain and the host name.
When verification fails, the scan returns `success: false` with the reason
(for example `self-signed certificate`) and sends no further request; it does
not retry without verification. Every tool's input accepts `verify_ssl`
(default `true`). Setting it to `false` lets that one scan read content from
whoever answers the connection, including an interceptor, so its results can
no longer be trusted.

`ssl_analyzer`, `ca_analyzer` and `pki_certificate_manager` exist to inspect
certificates, including broken ones: they read the certificate over an
unverified handshake, also attempt a verified one, and report an untrusted
certificate as a finding.

## Table of Contents

- [Authentication](#authentication)
- [Tool Management](#tool-management)
- [Tool Execution](#tool-execution)
- [System Monitoring](#system-monitoring)
- [Error Codes](#error-codes)
- [Rate Limiting](#rate-limiting)

---

## Authentication

Every request goes through the gateway, which authenticates the caller and
forwards the identity to the service as `X-Wildbox-*` headers with the
`X-Gateway-Secret` proof of origin. The credential is a JWT or a personal API
key created in the identity service:

```bash
curl -X GET https://<host>/api/v1/tools \
  -H "X-API-Key: your-api-key"
```

A request sent to the service port directly, without the gateway headers, is
answered with 401. The service's own `API_KEY` setting is not a credential:
the direct `X-API-Key` path was removed in #565.

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
| ------ | ------ | ---------- | ------------- |
| category | string | No | Filter by category: scanner, analyzer, enricher, responder |
| status | string | No | Filter by status: active, inactive, error |
| limit | integer | No | Number of results (default: 50) |
| offset | integer | No | Pagination offset |

**Request**:

```bash
curl -X GET "https://<host>/api/v1/tools?category=scanner&status=active" \
  -H "X-API-Key: your-api-key"
```

**Response (200 OK)**:

```json
{
  "count": 52,
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
curl -X GET https://<host>/api/v1/tools/nessus-001/info \
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

A tool runs synchronously, answering with its output, or asynchronously, as
a task that its submitter reads, cancels and lists through the task
endpoints. The request body is the tool's input, as `GET
/api/v1/tools/{tool_name}/info` describes it (`input_schema`).

### POST /tools/{tool_name}

Run a tool and wait for its output.

**Method**: `POST`
**Endpoint**: `/api/v1/tools/{tool_name}`
**Authentication**: Required (`tools:execute` for a scoped API key)

```bash
curl -X POST https://<host>/api/v1/tools/hash_generator \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"input_text": "wildbox", "hash_types": ["sha256"]}'
```

**Response (200 OK)**: the tool's output schema. A tool that acts for the
caller and refuses them answers 403, a tool that runs out of time 408.

---

### POST /tools/{tool_name}/async

Queue a tool execution and return at once with a task ID.

**Method**: `POST`
**Endpoint**: `/api/v1/tools/{tool_name}/async`
**Authentication**: Required (`tools:execute` for a scoped API key)

```bash
curl -X POST https://<host>/api/v1/tools/hash_generator/async \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"input_text": "wildbox", "hash_types": ["sha256"]}'
```

**Response (202 Accepted)**:

```json
{
  "task_id": "1b4e28ba-2fa1-41d2-883f-0016d3cca427",
  "status": "accepted",
  "tool_name": "hash_generator",
  "status_url": "/api/v1/tasks/1b4e28ba-2fa1-41d2-883f-0016d3cca427",
  "message": "Task submitted successfully. Use task_id to check status."
}
```

The service records who submitted the task before it queues it; answers
503 when it cannot (Redis or the task queue unreachable).

---

### Task visibility

A task belongs to the user who submitted it. Only that user can read,
cancel or list it. For anyone else, a teammate or an administrator
included, it does not exist: reading or cancelling it answers 404, the same
answer as for an unknown task ID, so the response does not confirm that a
task exists, and it is not in their list. A task without an owner record,
such as one submitted before owners were recorded, is not readable.

Owner records expire after a day; a result is kept for an hour after the
task finishes. The task endpoints have their own prefix, `/api/v1/tasks`,
because under `/api/v1/tools/` the segment after the prefix is a tool
name.

---

### GET /tasks/{task_id}

Status, and result once finished, of one of the caller's tasks.

**Method**: `GET`
**Endpoint**: `/api/v1/tasks/{task_id}`
**Authentication**: Required (`tools:read` for a scoped API key)

```bash
curl -X GET https://<host>/api/v1/tasks/1b4e28ba-2fa1-41d2-883f-0016d3cca427 \
  -H "X-API-Key: your-api-key"
```

**Response (200 OK) - Waiting or running**:

```json
{
  "task_id": "1b4e28ba-2fa1-41d2-883f-0016d3cca427",
  "state": "PENDING",
  "tool_name": "hash_generator",
  "submitted_at": 1790000000.0,
  "status": "pending",
  "message": "Task is waiting to be executed"
}
```

**Response (200 OK) - Finished**:

```json
{
  "task_id": "1b4e28ba-2fa1-41d2-883f-0016d3cca427",
  "state": "SUCCESS",
  "tool_name": "hash_generator",
  "submitted_at": 1790000000.0,
  "status": "completed",
  "error": null,
  "result": {"success": true, "hash_results": ["..."]},
  "duration": 0.012,
  "completed_at": "2026-10-03T10:00:01.234567"
}
```

`status` is `pending`, `running`, `retrying`, `completed`, `failed`,
`timeout`, `refused` (a tool that acts for the caller and does not
authorize them) or `cancelled`; `state` is Celery's. **404** for a task the
caller did not submit or that does not exist.

---

### DELETE /tasks/{task_id}

Cancel one of the caller's pending or running tasks.

**Method**: `DELETE`
**Endpoint**: `/api/v1/tasks/{task_id}`
**Authentication**: Required (`tools:execute` for a scoped API key)

```bash
curl -X DELETE https://<host>/api/v1/tasks/1b4e28ba-2fa1-41d2-883f-0016d3cca427 \
  -H "X-API-Key: your-api-key"
```

**Response (200 OK)**:

```json
{
  "task_id": "1b4e28ba-2fa1-41d2-883f-0016d3cca427",
  "status": "cancelled",
  "message": "Task cancellation requested"
}
```

**400** for a task that has finished; **404** for a task the caller did not
submit or that does not exist.

---

### GET /tasks

The caller's tasks of the last day, newest first.

**Method**: `GET`
**Endpoint**: `/api/v1/tasks`
**Authentication**: Required (`tools:read` for a scoped API key)

**Query Parameters**:

| Name | Type | Required | Description |
| ------ | ------ | ---------- | ------------- |
| limit | integer | No | 1 to 100 (default: 50) |

```bash
curl -X GET "https://<host>/api/v1/tasks?limit=20" \
  -H "X-API-Key: your-api-key"
```

**Response (200 OK)**:

```json
{
  "tasks": [
    {
      "task_id": "1b4e28ba-2fa1-41d2-883f-0016d3cca427",
      "tool_name": "hash_generator",
      "submitted_at": 1790000000.0,
      "state": "SUCCESS",
      "status": "completed",
      "status_url": "/api/v1/tasks/1b4e28ba-2fa1-41d2-883f-0016d3cca427"
    }
  ],
  "count": 1
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
curl http://localhost:8000/api/health
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
curl -X GET http://localhost:8000/api/system/info \
  -H "X-API-Key: your-api-key"
```

**Response (200 OK)**:

```json
{
  "service": "Wildbox Tools Service",
  "version": "1.0.0",
  "uptime_seconds": 604800,
  "tools_available": 52,
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
curl -X GET "http://localhost:8000/api/system/metrics?time_range=24h" \
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
| ------ | -------- | ------------- |
| 200 | OK | Request successful |
| 202 | Accepted | Tool execution submitted asynchronously |
| 400 | Bad Request | Invalid parameters or request body |
| 401 | Unauthorized | Missing or invalid API key |
| 404 | Not Found | Tool not found; task not found or not the caller's |
| 409 | Conflict | Tool not available or in error state |
| 503 | Service Unavailable | Asynchronous execution unavailable (Redis or queue down) |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Service error |

---

## Rate Limiting

The Tools Service enforces rate limits per API key:

- **Standard API Keys**: 100 requests/minute
- **Premium API Keys**: 1,000 requests/minute

Rate limit information is returned in response headers:

```yaml
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1730963100
```

---

## Examples

### Run a Tool Asynchronously and Wait for Its Result

```bash
TASK_ID=$(curl -s -X POST https://<host>/api/v1/tools/hash_generator/async \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"input_text": "wildbox", "hash_types": ["sha256"]}' | jq -r '.task_id')

echo "Task submitted: $TASK_ID"

while true; do
  TASK=$(curl -s "https://<host>/api/v1/tasks/$TASK_ID" \
    -H "X-API-Key: your-api-key")
  STATUS=$(echo "$TASK" | jq -r '.status')
  echo "Status: $STATUS"

  if [ "$STATUS" != "pending" ] && [ "$STATUS" != "running" ] && [ "$STATUS" != "retrying" ]; then
    echo "$TASK" | jq '.result'
    break
  fi
  sleep 2
done
```

### Queue Several Lookups and List Them

```bash
#!/bin/bash

for domain in example.com example.org; do
  curl -s -X POST "https://<host>/api/v1/tools/whois_lookup/async" \
    -H "X-API-Key: your-api-key" \
    -H "Content-Type: application/json" \
    -d "{\"domain\": \"$domain\"}" | jq -r '.task_id'
done

curl -s "https://<host>/api/v1/tasks" -H "X-API-Key: your-api-key" \
  | jq '.tasks[] | {task_id, tool_name, status}'
```

---

## Related Documentation

- [Security Policy](../../security/policy.md) - Authentication requirements
- [API Reference Hub](../../api-reference.html) - All service endpoints
- [Guardian Service API](../guardian/endpoints.md) - Asset management
- [Responder Service API](../responder/endpoints.md) - Incident response

