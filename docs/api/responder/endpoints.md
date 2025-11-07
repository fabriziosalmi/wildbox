# Responder Service API

**Service Port**: 8018
**Base URL**: `http://localhost:8018/api/v1`
**Authentication**: Bearer Token (JWT) required
**Documentation**: [Live Swagger UI](http://localhost:8018/docs) | [OpenAPI Schema](http://localhost:8018/openapi.json)

---

## Overview

The Responder Service orchestrates incident response and remediation workflows through SOAR (Security Orchestration, Automation, and Response) playbooks. It executes automated response actions, manages incident tickets, tracks remediation progress, and integrates with external connectors for alert triage, ticket creation, and remediation execution.

## Table of Contents

- [Authentication](#authentication)
- [Playbook Management](#playbook-management)
- [Execution & Monitoring](#execution--monitoring)
- [Connector Management](#connector-management)
- [Error Codes](#error-codes)
- [Rate Limiting](#rate-limiting)

---

## Authentication

All Responder Service endpoints require JWT Bearer token authentication:

```bash
curl -X GET http://localhost:8018/api/v1/playbooks \
  -H "Authorization: Bearer your-jwt-token"
```

---

## Playbook Management

### GET /playbooks

List all available SOAR playbooks.

**Method**: `GET`
**Endpoint**: `/api/v1/playbooks`
**Authentication**: Required (Bearer Token)
**Rate Limit**: 100 requests/minute

**Query Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| category | string | No | Filter by category: incident_response, malware, threat_intel, access_control |
| enabled | boolean | No | Filter by enabled status |
| limit | integer | No | Number of results (default: 50) |
| offset | integer | No | Pagination offset |
| search | string | No | Search playbook name or description |

**Request**:
```bash
curl -X GET "http://localhost:8018/api/v1/playbooks?category=incident_response&enabled=true" \
  -H "Authorization: Bearer your-jwt-token"
```

**Response (200 OK)**:
```json
{
  "count": 24,
  "results": [
    {
      "id": "pb-001",
      "name": "Malware Detection Response",
      "category": "malware",
      "description": "Automated response to malware detection alerts",
      "enabled": true,
      "created_at": "2024-06-15T10:30:00Z",
      "updated_at": "2024-11-07T14:25:00Z",
      "version": "2.1",
      "triggers": ["malware_detected", "suspicious_process"],
      "actions": [
        "isolate_host",
        "kill_process",
        "create_ticket",
        "notify_team"
      ],
      "execution_timeout_seconds": 600,
      "success_rate": 0.98
    },
    {
      "id": "pb-002",
      "name": "Brute Force Attack Response",
      "category": "access_control",
      "description": "Respond to repeated failed authentication attempts",
      "enabled": true,
      "triggers": ["failed_login_threshold"],
      "actions": ["block_ip", "reset_password", "create_ticket", "alert_security"]
    }
  ],
  "pagination": {
    "limit": 50,
    "offset": 0,
    "total": 24
  }
}
```

---

### GET /playbooks/{playbook_id}

Get detailed information about a specific playbook.

**Method**: `GET`
**Endpoint**: `/api/v1/playbooks/{playbook_id}`
**Authentication**: Required (Bearer Token)

**Path Parameters**:

| Name | Type | Description |
|------|------|-------------|
| playbook_id | string | Playbook identifier |

**Request**:
```bash
curl -X GET http://localhost:8018/api/v1/playbooks/pb-001 \
  -H "Authorization: Bearer your-jwt-token"
```

**Response (200 OK)**:
```json
{
  "id": "pb-001",
  "name": "Malware Detection Response",
  "category": "malware",
  "description": "Comprehensive automated response to malware detection alerts",
  "enabled": true,
  "version": "2.1",
  "created_by": "security-team",
  "created_at": "2024-06-15T10:30:00Z",
  "updated_at": "2024-11-07T14:25:00Z",
  "triggers": [
    {
      "type": "malware_detected",
      "source": "antivirus",
      "severity": "critical"
    },
    {
      "type": "suspicious_process",
      "source": "edr",
      "severity": "high"
    }
  ],
  "steps": [
    {
      "step_id": 1,
      "name": "Isolate Host",
      "action": "isolate_host",
      "connector": "network_isolation",
      "parameters": {
        "action": "network_isolation",
        "duration_minutes": 60
      },
      "timeout_seconds": 60,
      "retry_count": 2
    },
    {
      "step_id": 2,
      "name": "Kill Malicious Process",
      "action": "kill_process",
      "connector": "endpoint_security",
      "parameters": {
        "process_criteria": "detection_source"
      },
      "timeout_seconds": 30
    },
    {
      "step_id": 3,
      "name": "Create Incident Ticket",
      "action": "create_ticket",
      "connector": "jira",
      "parameters": {
        "project": "SEC",
        "issue_type": "Incident",
        "priority": "Highest"
      }
    },
    {
      "step_id": 4,
      "name": "Notify Security Team",
      "action": "notify_team",
      "connector": "slack",
      "parameters": {
        "channel": "#security-incidents",
        "mention_on_call": true
      }
    }
  ],
  "execution_timeout_seconds": 600,
  "success_rate": 0.98,
  "last_run": "2024-11-07T16:30:00Z",
  "total_executions": 156
}
```

---

### POST /playbooks/{playbook_id}/execute

Execute a playbook with specified parameters.

**Method**: `POST`
**Endpoint**: `/api/v1/playbooks/{playbook_id}/execute`
**Authentication**: Required (Bearer Token)

**Path Parameters**:

| Name | Type | Description |
|------|------|-------------|
| playbook_id | string | Playbook identifier |

**Request Body**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| trigger_data | object | Yes | Data from the triggering event |
| alert_id | string | No | Associated alert ID |
| incident_id | string | No | Associated incident ID |
| priority | string | No | Priority: low, normal, high, critical (default: normal) |

**Request**:
```bash
curl -X POST http://localhost:8018/api/v1/playbooks/pb-001/execute \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{
    "trigger_data": {
      "host": "workstation-42",
      "process_name": "malware.exe",
      "severity": "critical"
    },
    "alert_id": "alert-12345",
    "priority": "critical"
  }'
```

**Response (202 Accepted)**:
```json
{
  "run_id": "run-550e8400-e29b-41d4-a716-446655440000",
  "playbook_id": "pb-001",
  "playbook_name": "Malware Detection Response",
  "status": "started",
  "created_at": "2024-11-07T18:35:00Z",
  "started_at": "2024-11-07T18:35:02Z",
  "completed_at": null,
  "progress": "Step 1/4: Isolating host..."
}
```

---

## Execution & Monitoring

### GET /runs/{run_id}

Get the status and results of a playbook execution.

**Method**: `GET`
**Endpoint**: `/api/v1/runs/{run_id}`
**Authentication**: Required (Bearer Token)

**Path Parameters**:

| Name | Type | Description |
|------|------|-------------|
| run_id | string | Execution run identifier |

**Request**:
```bash
curl -X GET http://localhost:8018/api/v1/runs/run-550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer your-jwt-token"
```

**Response (200 OK) - In Progress**:
```json
{
  "run_id": "run-550e8400-e29b-41d4-a716-446655440000",
  "playbook_id": "pb-001",
  "playbook_name": "Malware Detection Response",
  "status": "running",
  "created_at": "2024-11-07T18:35:00Z",
  "started_at": "2024-11-07T18:35:02Z",
  "completed_at": null,
  "current_step": 2,
  "total_steps": 4,
  "progress": "Step 2/4: Killing malicious process...",
  "steps_completed": [
    {
      "step_id": 1,
      "name": "Isolate Host",
      "status": "success",
      "started_at": "2024-11-07T18:35:02Z",
      "completed_at": "2024-11-07T18:35:45Z",
      "duration_seconds": 43,
      "result": {
        "host": "workstation-42",
        "action": "isolated",
        "isolation_id": "iso-789"
      }
    }
  ]
}
```

**Response (200 OK) - Completed**:
```json
{
  "run_id": "run-550e8400-e29b-41d4-a716-446655440000",
  "playbook_id": "pb-001",
  "playbook_name": "Malware Detection Response",
  "status": "success",
  "created_at": "2024-11-07T18:35:00Z",
  "started_at": "2024-11-07T18:35:02Z",
  "completed_at": "2024-11-07T18:37:32Z",
  "total_duration_seconds": 150,
  "current_step": 4,
  "total_steps": 4,
  "steps_completed": [
    {
      "step_id": 1,
      "name": "Isolate Host",
      "status": "success",
      "started_at": "2024-11-07T18:35:02Z",
      "completed_at": "2024-11-07T18:35:45Z",
      "duration_seconds": 43,
      "result": {
        "host": "workstation-42",
        "action": "isolated"
      }
    },
    {
      "step_id": 2,
      "name": "Kill Malicious Process",
      "status": "success",
      "started_at": "2024-11-07T18:35:45Z",
      "completed_at": "2024-11-07T18:35:62Z",
      "duration_seconds": 17,
      "result": {
        "process": "malware.exe",
        "action": "terminated"
      }
    },
    {
      "step_id": 3,
      "name": "Create Incident Ticket",
      "status": "success",
      "started_at": "2024-11-07T18:35:62Z",
      "completed_at": "2024-11-07T18:36:15Z",
      "duration_seconds": 53,
      "result": {
        "ticket_id": "SEC-2024-001234",
        "url": "https://jira.example.com/browse/SEC-2024-001234"
      }
    },
    {
      "step_id": 4,
      "name": "Notify Security Team",
      "status": "success",
      "started_at": "2024-11-07T18:36:15Z",
      "completed_at": "2024-11-07T18:36:32Z",
      "duration_seconds": 17,
      "result": {
        "channel": "#security-incidents",
        "message_id": "msg-xyz789"
      }
    }
  ],
  "summary": {
    "host_isolated": true,
    "process_terminated": true,
    "ticket_created": "SEC-2024-001234",
    "team_notified": true
  }
}
```

---

### GET /runs

List playbook executions with filtering and pagination.

**Method**: `GET`
**Endpoint**: `/api/v1/runs`
**Authentication**: Required (Bearer Token)

**Query Parameters**:

| Name | Type | Description |
|------|------|-------------|
| playbook_id | string | Filter by playbook |
| status | string | Filter by status: running, success, failed, cancelled |
| limit | integer | Results per page (default: 50) |
| offset | integer | Pagination offset |
| time_range | string | 1h, 24h, 7d, 30d |

**Request**:
```bash
curl -X GET "http://localhost:8018/api/v1/runs?status=success&time_range=24h" \
  -H "Authorization: Bearer your-jwt-token"
```

**Response (200 OK)**:
```json
{
  "count": 45,
  "results": [
    {
      "run_id": "run-550e8400-e29b-41d4-a716-446655440000",
      "playbook_id": "pb-001",
      "playbook_name": "Malware Detection Response",
      "status": "success",
      "created_at": "2024-11-07T18:35:00Z",
      "completed_at": "2024-11-07T18:37:32Z",
      "duration_seconds": 150
    }
  ]
}
```

---

### DELETE /runs/{run_id}

Cancel a running playbook execution.

**Method**: `DELETE`
**Endpoint**: `/api/v1/runs/{run_id}`
**Authentication**: Required (Bearer Token)

**Request**:
```bash
curl -X DELETE http://localhost:8018/api/v1/runs/run-550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer your-jwt-token"
```

**Response (200 OK)**:
```json
{
  "message": "Execution cancelled",
  "run_id": "run-550e8400-e29b-41d4-a716-446655440000",
  "status": "cancelled"
}
```

---

## Connector Management

### GET /connectors

List all configured connectors for playbook actions.

**Method**: `GET`
**Endpoint**: `/api/v1/connectors`
**Authentication**: Required (Bearer Token)

**Query Parameters**:

| Name | Type | Description |
|------|------|-------------|
| category | string | Filter by category: ticketing, notification, orchestration, threat_intel |
| status | string | Filter by status: active, inactive, error |

**Request**:
```bash
curl -X GET "http://localhost:8018/api/v1/connectors?status=active" \
  -H "Authorization: Bearer your-jwt-token"
```

**Response (200 OK)**:
```json
{
  "count": 12,
  "results": [
    {
      "id": "conn-jira-001",
      "name": "Jira - Ticketing",
      "category": "ticketing",
      "platform": "Atlassian JIRA",
      "status": "active",
      "version": "1.0",
      "supported_actions": [
        "create_issue",
        "update_issue",
        "add_comment",
        "transition_issue",
        "assign_issue"
      ],
      "last_tested": "2024-11-07T16:30:00Z"
    },
    {
      "id": "conn-slack-001",
      "name": "Slack - Notifications",
      "category": "notification",
      "platform": "Slack",
      "status": "active",
      "supported_actions": [
        "send_message",
        "post_file",
        "update_status",
        "create_channel"
      ]
    }
  ]
}
```

---

## Error Codes

| Code | Status | Description |
|------|--------|-------------|
| 200 | OK | Request successful |
| 202 | Accepted | Playbook execution started |
| 400 | Bad Request | Invalid request parameters |
| 401 | Unauthorized | Missing or invalid token |
| 404 | Not Found | Playbook or execution not found |
| 409 | Conflict | Playbook disabled or execution already running |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Service error |

---

## Rate Limiting

The Responder Service enforces rate limits per token:

- **Standard tokens**: 100 requests/minute
- **Privileged tokens**: 1,000 requests/minute

Rate limit information is returned in response headers:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1730963100
```

---

## Examples

### Automated Incident Response Workflow

```bash
# 1. List available playbooks
PLAYBOOKS=$(curl -s http://localhost:8018/api/v1/playbooks?category=malware \
  -H "Authorization: Bearer $TOKEN" | jq '.')

# 2. Execute malware response playbook
RUN_ID=$(curl -s -X POST http://localhost:8018/api/v1/playbooks/pb-001/execute \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "trigger_data": {
      "host": "infected-host",
      "process": "malware.exe",
      "severity": "critical"
    },
    "priority": "critical"
  }' | jq -r '.run_id')

echo "Playbook execution started: $RUN_ID"

# 3. Monitor execution progress
while true; do
  RUN=$(curl -s http://localhost:8018/api/v1/runs/$RUN_ID \
    -H "Authorization: Bearer $TOKEN")

  STATUS=$(echo "$RUN" | jq -r '.status')
  PROGRESS=$(echo "$RUN" | jq -r '.progress')

  echo "[$STATUS] $PROGRESS"

  if [[ "$STATUS" == "success" ]] || [[ "$STATUS" == "failed" ]]; then
    echo "Execution complete!"
    echo "$RUN" | jq '.summary'
    break
  fi

  sleep 2
done
```

### Trigger Playbook from Alert

```bash
#!/bin/bash

# Receive alert from SIEM
ALERT_DATA=$(cat <<'EOF'
{
  "alert_id": "alert-001",
  "severity": "critical",
  "title": "Suspicious Activity Detected",
  "host": "prod-web-01",
  "alert_type": "suspicious_network_activity"
}
EOF
)

# Execute appropriate playbook
if grep -q "suspicious_network" <<< "$ALERT_DATA"; then
  PLAYBOOK_ID="pb-network-isolation"
else
  PLAYBOOK_ID="pb-generic-response"
fi

# Execute playbook
curl -X POST "http://localhost:8018/api/v1/playbooks/$PLAYBOOK_ID/execute" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"trigger_data\": $ALERT_DATA,
    \"alert_id\": \"$(echo $ALERT_DATA | jq -r '.alert_id')\",
    \"priority\": \"critical\"
  }"
```

---

## Related Documentation

- [Security Policy](../../security/policy.md) - Authentication requirements
- [API Reference Hub](../api-reference.html) - All service endpoints
- [Guardian Service API](../guardian/endpoints.md) - Asset and vulnerability management
- [Tools Service API](../tools/endpoints.md) - Tool execution
- [Quickstart Guide](../../guides/quickstart.md) - Getting started with APIs

---

**Last Updated**: November 7, 2024
**API Version**: v1
**Status**: Stable
**Base Port**: 8018
