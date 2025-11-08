# Open Security Guardian - Comprehensive API Endpoint Documentation

## Overview

The Open Security Guardian is a Django-based REST API for vulnerability management, compliance tracking, asset inventory, and security reporting. This document provides a complete inventory of all HTTP endpoints organized by category.

**Base URL:** `http://localhost:8000/api/v1/`

---

## Authentication & Authorization

### Authentication Methods

1. **API Key Authentication**
   - Header: `X-API-Key: your-api-key-here`
   - Alternative: `Authorization: Bearer your-api-key-here`
   - Class: `APIKeyAuthentication`

2. **JWT Token Authentication**
   - Header: `Authorization: Bearer your-jwt-token-here`
   - Class: `SessionAuthentication`

3. **Session Authentication**
   - Standard Django session authentication for web interface

### Permission Classes

- `IsAuthenticated` - Most endpoints require authentication
- `IsAssetManager` - Asset management endpoints
- `IsComplianceManager` - Compliance management endpoints
- `IsSecurityAnalyst` - Security analysis endpoints
- `IsVulnerabilityManager` - Vulnerability management endpoints

---

## Rate Limiting

- **Anonymous users:** 100 requests/hour
- **Authenticated users:** 1000 requests/hour
- **API key users:** 5000 requests/hour

Response headers include:
- `X-RateLimit-Limit`
- `X-RateLimit-Remaining`
- `X-RateLimit-Reset`

---

## Core Infrastructure Endpoints

### Health Check
- **GET** `/health/`
  - Description: System health status check
  - Authentication: None (public endpoint)
  - Response: Health status, database/redis/system metrics
  - Status Codes: 200 OK (healthy), 503 Service Unavailable (unhealthy)

### Metrics (Prometheus)
- **GET** `/metrics/`
  - Description: Prometheus metrics endpoint
  - Authentication: None (public endpoint)
  - Response: Prometheus format metrics
  - Status Codes: 200 OK, 404 Not Found (if disabled)

### API Schema & Documentation
- **GET** `/api/schema/`
  - Description: OpenAPI/Swagger schema in JSON
  - Authentication: None
  - Response: Complete OpenAPI specification

- **GET** `/docs/`
  - Description: Swagger UI documentation interface
  - Authentication: None
  - Content-Type: HTML

- **GET** `/redoc/`
  - Description: ReDoc API documentation interface
  - Authentication: None
  - Content-Type: HTML

---

## Assets Management (`/api/v1/assets/`)

### Asset Endpoints

#### List Assets
- **GET** `/assets/`
  - Parameters:
    - `asset_type` (filter)
    - `environment` (filter)
    - `criticality` (filter)
    - `is_active` (filter)
    - `search` (search in hostname, name, description)
    - `page` (pagination)
    - `page_size` (max 100)
    - `ordering` (name, criticality, last_seen, created_at)
  - Permission: IsAuthenticated
  - Response: Paginated list of assets

#### Create Asset
- **POST** `/assets/`
  - Body: hostname, ip_address, asset_type, environment, criticality, description, owner, location
  - Permission: IsAuthenticated
  - Status Code: 201 Created

#### Get Asset Details
- **GET** `/assets/{id}/`
  - Permission: IsAuthenticated
  - Response: Detailed asset information

#### Update Asset
- **PUT** `/assets/{id}/`
  - Body: criticality, description, and other asset fields
  - Permission: IsAuthenticated
  - Status Code: 200 OK

#### Partial Update Asset
- **PATCH** `/assets/{id}/`
  - Body: Partial asset fields
  - Permission: IsAuthenticated
  - Status Code: 200 OK

#### Delete Asset
- **DELETE** `/assets/{id}/`
  - Permission: IsAuthenticated
  - Status Code: 204 No Content

#### Scan Asset
- **POST** `/assets/{id}/scan/`
  - Description: Trigger vulnerability scan for asset
  - Body: (optional scan parameters)
  - Permission: IsAuthenticated
  - Response: Task ID and status

#### Add Software to Asset
- **POST** `/assets/{id}/add_software/`
  - Body: name, vendor, version, is_critical
  - Permission: IsAuthenticated
  - Status Code: 201 Created

#### Add Port to Asset
- **POST** `/assets/{id}/add_port/`
  - Body: port_number, protocol, state, service, banner
  - Permission: IsAuthenticated
  - Status Code: 201 Created

#### Add Tag to Asset
- **POST** `/assets/{id}/add_tag/`
  - Body: tag (required)
  - Permission: IsAuthenticated
  - Response: Confirmation message

#### Remove Tag from Asset
- **DELETE** `/assets/{id}/remove_tag/`
  - Body: tag (required)
  - Permission: IsAuthenticated
  - Response: Confirmation message

#### Discover Assets
- **POST** `/assets/discover/`
  - Body: network_range (required), scan_type (default: basic)
  - Permission: IsAuthenticated
  - Response: Task ID

#### Asset Statistics
- **GET** `/assets/statistics/`
  - Description: Asset count by type, criticality, status, recently discovered, with vulnerabilities
  - Permission: IsAuthenticated
  - Response: Statistics object

### Environment Endpoints

#### List Environments
- **GET** `/environments/`
  - Parameters: search, page, page_size, ordering
  - Permission: IsAuthenticated

#### Create Environment
- **POST** `/environments/`
  - Body: name, description
  - Permission: IsAuthenticated
  - Status Code: 201 Created

#### Get Environment Details
- **GET** `/environments/{id}/`
  - Permission: IsAuthenticated

#### Update Environment
- **PUT** `/environments/{id}/`
  - Permission: IsAuthenticated

#### Delete Environment
- **DELETE** `/environments/{id}/`
  - Permission: IsAuthenticated

### Business Function Endpoints

#### List Business Functions
- **GET** `/business-functions/`
  - Parameters: search, page, page_size, ordering
  - Permission: IsAuthenticated

#### Create Business Function
- **POST** `/business-functions/`
  - Body: name, description
  - Permission: IsAuthenticated

#### Get Business Function
- **GET** `/business-functions/{id}/`
  - Permission: IsAuthenticated

#### Update Business Function
- **PUT** `/business-functions/{id}/`
  - Permission: IsAuthenticated

#### Delete Business Function
- **DELETE** `/business-functions/{id}/`
  - Permission: IsAuthenticated

### Asset Group Endpoints

#### List Asset Groups
- **GET** `/groups/`
  - Parameters: search, page, page_size, ordering
  - Permission: IsAuthenticated

#### Create Asset Group
- **POST** `/groups/`
  - Body: name, description
  - Permission: IsAuthenticated

#### Get Asset Group
- **GET** `/groups/{id}/`
  - Permission: IsAuthenticated

#### Update Asset Group
- **PUT** `/groups/{id}/`
  - Permission: IsAuthenticated

#### Delete Asset Group
- **DELETE** `/groups/{id}/`
  - Permission: IsAuthenticated

#### Apply Auto-Assignment Rules
- **POST** `/groups/{id}/apply_rules/`
  - Description: Apply auto-assignment rules to group
  - Permission: IsAuthenticated

#### Add Assets to Group
- **POST** `/groups/{id}/add_assets/`
  - Body: asset_ids (list)
  - Permission: IsAuthenticated

#### Remove Assets from Group
- **DELETE** `/groups/{id}/remove_assets/`
  - Body: asset_ids (list)
  - Permission: IsAuthenticated

### Asset Discovery Rule Endpoints

#### List Discovery Rules
- **GET** `/discovery-rules/`
  - Parameters: search, page, page_size, ordering
  - Permission: IsAuthenticated, IsAssetManager

#### Create Discovery Rule
- **POST** `/discovery-rules/`
  - Body: name, description, network_range, scan_type
  - Permission: IsAuthenticated, IsAssetManager

#### Get Discovery Rule
- **GET** `/discovery-rules/{id}/`
  - Permission: IsAuthenticated, IsAssetManager

#### Update Discovery Rule
- **PUT** `/discovery-rules/{id}/`
  - Permission: IsAuthenticated, IsAssetManager

#### Delete Discovery Rule
- **DELETE** `/discovery-rules/{id}/`
  - Permission: IsAuthenticated, IsAssetManager

#### Execute Discovery Rule
- **POST** `/discovery-rules/{id}/execute/`
  - Description: Execute discovery rule immediately
  - Permission: IsAuthenticated, IsAssetManager

#### Enable Discovery Rule
- **POST** `/discovery-rules/{id}/enable/`
  - Permission: IsAuthenticated, IsAssetManager

#### Disable Discovery Rule
- **POST** `/discovery-rules/{id}/disable/`
  - Permission: IsAuthenticated, IsAssetManager

### Asset Software Endpoints

#### List Software
- **GET** `/software/`
  - Parameters: asset (filter), name (filter), vendor (filter), is_critical (filter), search, page, page_size
  - Permission: IsAuthenticated

#### Create Software
- **POST** `/software/`
  - Body: asset, name, vendor, version, is_critical
  - Permission: IsAuthenticated

#### Get Software Details
- **GET** `/software/{id}/`
  - Permission: IsAuthenticated

#### Update Software
- **PUT** `/software/{id}/`
  - Permission: IsAuthenticated

#### Delete Software
- **DELETE** `/software/{id}/`
  - Permission: IsAuthenticated

#### Software Inventory
- **GET** `/software/inventory/`
  - Description: Get software inventory across all assets (name, vendor, asset_count, version_count)
  - Permission: IsAuthenticated

### Asset Port Endpoints

#### List Ports
- **GET** `/ports/`
  - Parameters: asset (filter), port_number (filter), protocol (filter), state (filter), service (filter), search, page, page_size
  - Permission: IsAuthenticated

#### Create Port
- **POST** `/ports/`
  - Body: asset, port_number, protocol, state, service, banner
  - Permission: IsAuthenticated

#### Get Port Details
- **GET** `/ports/{id}/`
  - Permission: IsAuthenticated

#### Update Port
- **PUT** `/ports/{id}/`
  - Permission: IsAuthenticated

#### Delete Port
- **DELETE** `/ports/{id}/`
  - Permission: IsAuthenticated

#### Port Summary
- **GET** `/ports/summary/`
  - Description: Get port summary across all assets (open ports by number, protocol, service)
  - Permission: IsAuthenticated

---

## Vulnerabilities Management (`/api/v1/vulnerabilities/`)

### Vulnerability Endpoints

#### List Vulnerabilities
- **GET** `/`
  - Parameters:
    - `severity` (critical, high, medium, low)
    - `status` (open, in_progress, resolved, false_positive)
    - `asset` (asset ID)
    - `cve_id` (filter)
    - `discovered_after` (ISO date)
    - `discovered_before` (ISO date)
    - `search` (title, description, CVE ID)
    - `page`, `page_size`
    - `ordering` (risk_score, cvss_v3_score, created_at, due_date, severity)
  - Permission: IsAuthenticated
  - Response: Paginated list of vulnerabilities

#### Create Vulnerability
- **POST** `/`
  - Body: title, description, severity, cvss_score, cve_id, asset, port, protocol, proof_of_concept
  - Permission: IsAuthenticated
  - Status Code: 201 Created

#### Get Vulnerability Details
- **GET** `/{id}/`
  - Permission: IsAuthenticated
  - Response: Detailed vulnerability information

#### Update Vulnerability
- **PUT** `/{id}/`
  - Permission: IsAuthenticated

#### Partial Update Vulnerability
- **PATCH** `/{id}/`
  - Body: status, assigned_to, notes (partial fields)
  - Permission: IsAuthenticated

#### Delete Vulnerability
- **DELETE** `/{id}/`
  - Permission: IsAuthenticated

#### Assign Vulnerability
- **POST** `/{id}/assign/`
  - Body: assigned_to (user ID), assignee_group
  - Permission: IsAuthenticated
  - Side Effect: Triggers notification task

#### Close Vulnerability
- **POST** `/{id}/close/`
  - Body: reason, resolution_method (fixed, mitigated, accepted)
  - Permission: IsAuthenticated
  - Side Effect: Creates history entry, updates status to RESOLVED

#### Reopen Vulnerability
- **POST** `/{id}/reopen/`
  - Body: reason
  - Permission: IsAuthenticated
  - Side Effect: Creates history entry, updates status to OPEN

#### Add Tag to Vulnerability
- **POST** `/{id}/add_tag/`
  - Body: tag (required)
  - Permission: IsAuthenticated

#### Remove Tag from Vulnerability
- **POST** `/{id}/remove_tag/`
  - Body: tag (required)
  - Permission: IsAuthenticated

#### Vulnerability History
- **GET** `/{id}/history/`
  - Description: Get change history for vulnerability
  - Permission: IsAuthenticated
  - Response: List of history entries (field_name, old_value, new_value, changed_by, changed_at)

#### Vulnerability Attachments
- **GET** `/{id}/attachments/`
  - Description: Get attachments for vulnerability
  - Permission: IsAuthenticated
  - Response: List of attachments

#### Bulk Action on Vulnerabilities
- **POST** `/bulk_action/`
  - Body: vulnerability_ids (list), action (assign, close, tag, priority), additional action-specific fields
  - Permission: IsAuthenticated
  - Response: Count of updated vulnerabilities

#### Vulnerability Statistics
- **GET** `/stats/`
  - Description: Comprehensive vulnerability statistics
  - Permission: IsAuthenticated
  - Response: total_vulnerabilities, by severity, by status, overdue_count, avg_risk_score, avg_resolution_time_days

#### Vulnerability Trends
- **GET** `/trends/`
  - Parameters: days (default 30)
  - Permission: IsAuthenticated
  - Response: Daily trend data (discovered_count, resolved_count, total_open, avg_risk_score)

### Vulnerability Template Endpoints

#### List Templates
- **GET** `/templates/`
  - Parameters: search, page, page_size, ordering
  - Permission: IsAuthenticated

#### Create Template
- **POST** `/templates/`
  - Body: title, description, severity, cve_id, category
  - Permission: IsAuthenticated

#### Get Template Details
- **GET** `/templates/{id}/`
  - Permission: IsAuthenticated

#### Update Template
- **PUT** `/templates/{id}/`
  - Permission: IsAuthenticated

#### Delete Template
- **DELETE** `/templates/{id}/`
  - Permission: IsAuthenticated

### Vulnerability Assessment Endpoints

#### List Assessments
- **GET** `/assessments/`
  - Parameters: vulnerability (filter), exploit_available (filter), exploit_public (filter), page, page_size
  - Permission: IsAuthenticated

#### Create Assessment
- **POST** `/assessments/`
  - Body: vulnerability, exploit_available, exploit_public, notes
  - Permission: IsAuthenticated

#### Get Assessment Details
- **GET** `/assessments/{id}/`
  - Permission: IsAuthenticated

#### Update Assessment
- **PUT** `/assessments/{id}/`
  - Permission: IsAuthenticated

#### Delete Assessment
- **DELETE** `/assessments/{id}/`
  - Permission: IsAuthenticated

---

## Scanners Management (`/api/v1/scanners/`)

### Scanner Endpoints

#### List Scanners
- **GET** `/scanners/`
  - Parameters: scanner_type (filter), status (filter), search, page, page_size, ordering
  - Permission: IsAuthenticated

#### Create Scanner
- **POST** `/scanners/`
  - Body: name, description, scanner_type, hostname, port, credentials, verify_ssl, is_active
  - Permission: IsAuthenticated

#### Get Scanner Details
- **GET** `/scanners/{id}/`
  - Permission: IsAuthenticated

#### Update Scanner
- **PUT** `/scanners/{id}/`
  - Permission: IsAuthenticated

#### Delete Scanner
- **DELETE** `/scanners/{id}/`
  - Permission: IsAuthenticated

#### Test Scanner Connection
- **POST** `/scanners/{id}/test_connection/`
  - Description: Test connection to scanner
  - Permission: IsAuthenticated
  - Response: success/failure status

#### Scanner Statistics
- **GET** `/scanners/stats/`
  - Description: Total scanners, active scanners, inactive scanners
  - Permission: IsAuthenticated

### Scan Profile Endpoints

#### List Scan Profiles
- **GET** `/scan-profiles/`
  - Parameters: scanner (filter), search, page, page_size, ordering
  - Permission: IsAuthenticated

#### Create Scan Profile
- **POST** `/scan-profiles/`
  - Body: name, description, scanner, profile_config
  - Permission: IsAuthenticated

#### Get Profile Details
- **GET** `/scan-profiles/{id}/`
  - Permission: IsAuthenticated

#### Update Profile
- **PUT** `/scan-profiles/{id}/`
  - Permission: IsAuthenticated

#### Delete Profile
- **DELETE** `/scan-profiles/{id}/`
  - Permission: IsAuthenticated

### Scan Endpoints

#### List Scans
- **GET** `/scans/`
  - Parameters: scanner (filter), profile (filter), status (filter), search, page, page_size, ordering
  - Permission: IsAuthenticated

#### Create Scan
- **POST** `/scans/`
  - Body: name, scanner, profile, targets, description
  - Permission: IsAuthenticated

#### Get Scan Details
- **GET** `/scans/{id}/`
  - Permission: IsAuthenticated

#### Update Scan
- **PUT** `/scans/{id}/`
  - Permission: IsAuthenticated

#### Delete Scan
- **DELETE** `/scans/{id}/`
  - Permission: IsAuthenticated

#### Start Scan
- **POST** `/scans/{id}/start/`
  - Description: Start a scan
  - Permission: IsAuthenticated
  - Side Effect: Updates scan status to 'running'

#### Stop Scan
- **POST** `/scans/{id}/stop/`
  - Description: Stop a running scan
  - Permission: IsAuthenticated
  - Side Effect: Updates scan status to 'stopped'

#### Pause Scan
- **POST** `/scans/{id}/pause/`
  - Description: Pause a scan
  - Permission: IsAuthenticated
  - Side Effect: Updates scan status to 'paused'

#### Resume Scan
- **POST** `/scans/{id}/resume/`
  - Description: Resume a paused scan
  - Permission: IsAuthenticated
  - Side Effect: Updates scan status to 'running'

#### Get Scan Results
- **GET** `/scans/{id}/results/`
  - Description: Get results for a specific scan
  - Permission: IsAuthenticated

#### Import Scan Results
- **POST** `/scans/import_results/`
  - Body: scan_type, file/data
  - Permission: IsAuthenticated

### Scan Result Endpoints

#### List Scan Results
- **GET** `/scan-results/`
  - Parameters: scan (filter), severity (filter), processed (filter), vulnerability_created (filter), search, page, page_size, ordering
  - Permission: IsAuthenticated

#### Get Result Details
- **GET** `/scan-results/{id}/`
  - Permission: IsAuthenticated

#### Update Result
- **PUT** `/scan-results/{id}/`
  - Permission: IsAuthenticated

#### Delete Result
- **DELETE** `/scan-results/{id}/`
  - Permission: IsAuthenticated

### Scan Schedule Endpoints

#### List Schedules
- **GET** `/scan-schedules/`
  - Parameters: scanner (filter), is_active (filter), search, page, page_size, ordering
  - Permission: IsAuthenticated

#### Create Schedule
- **POST** `/scan-schedules/`
  - Body: name, description, scanner, frequency, next_run, is_active
  - Permission: IsAuthenticated

#### Get Schedule Details
- **GET** `/scan-schedules/{id}/`
  - Permission: IsAuthenticated

#### Update Schedule
- **PUT** `/scan-schedules/{id}/`
  - Permission: IsAuthenticated

#### Delete Schedule
- **DELETE** `/scan-schedules/{id}/`
  - Permission: IsAuthenticated

#### Trigger Schedule
- **POST** `/scan-schedules/{id}/trigger/`
  - Description: Manually trigger a scheduled scan
  - Permission: IsAuthenticated

#### Enable Schedule
- **POST** `/scan-schedules/{id}/enable/`
  - Description: Enable a scan schedule
  - Permission: IsAuthenticated

#### Disable Schedule
- **POST** `/scan-schedules/{id}/disable/`
  - Description: Disable a scan schedule
  - Permission: IsAuthenticated

---

## Remediation Management (`/api/v1/remediation/`)

### Remediation Ticket Endpoints

#### List Tickets
- **GET** `/tickets/`
  - Parameters: status (filter), priority (filter), assigned_to (filter), ticketing_system (filter), search, page, page_size, ordering
  - Permission: IsAuthenticated

#### Create Ticket
- **POST** `/tickets/`
  - Body: vulnerability, workflow, title, description, priority, due_date, assigned_to
  - Permission: IsAuthenticated

#### Get Ticket Details
- **GET** `/tickets/{id}/`
  - Permission: IsAuthenticated

#### Update Ticket
- **PUT** `/tickets/{id}/`
  - Permission: IsAuthenticated

#### Delete Ticket
- **DELETE** `/tickets/{id}/`
  - Permission: IsAuthenticated

#### Assign Ticket
- **POST** `/tickets/{id}/assign/`
  - Body: assignee_id (required)
  - Permission: IsAuthenticated

#### Update Ticket Status
- **POST** `/tickets/{id}/update_status/`
  - Body: status (required)
  - Permission: IsAuthenticated

#### Sync with External System
- **POST** `/tickets/{id}/sync_external/`
  - Description: Sync with external ticketing system (Jira, ServiceNow)
  - Permission: IsAuthenticated

### Remediation Workflow Endpoints

#### List Workflows
- **GET** `/workflows/`
  - Parameters: vulnerability (filter), status (filter), priority (filter), assigned_to (filter), search, page, page_size, ordering
  - Permission: IsAuthenticated

#### Create Workflow
- **POST** `/workflows/`
  - Body: name, description, vulnerability, priority, due_date
  - Permission: IsAuthenticated

#### Get Workflow Details
- **GET** `/workflows/{id}/`
  - Permission: IsAuthenticated

#### Update Workflow
- **PUT** `/workflows/{id}/`
  - Permission: IsAuthenticated

#### Delete Workflow
- **DELETE** `/workflows/{id}/`
  - Permission: IsAuthenticated

#### Start Workflow
- **POST** `/workflows/{id}/start/`
  - Description: Start workflow execution
  - Permission: IsAuthenticated

#### Pause Workflow
- **POST** `/workflows/{id}/pause/`
  - Description: Pause workflow execution
  - Permission: IsAuthenticated

#### Complete Workflow
- **POST** `/workflows/{id}/complete/`
  - Description: Mark workflow as completed
  - Permission: IsAuthenticated

#### Workflow Progress
- **GET** `/workflows/{id}/progress/`
  - Description: Get workflow progress (total_steps, completed_steps, progress_percentage)
  - Permission: IsAuthenticated

### Remediation Step Endpoints

#### List Steps
- **GET** `/steps/`
  - Parameters: workflow (filter), status (filter), assigned_to (filter), step_type (filter), search, page, page_size, ordering
  - Permission: IsAuthenticated

#### Create Step
- **POST** `/steps/`
  - Body: workflow, title, description, order, due_date, step_type
  - Permission: IsAuthenticated

#### Get Step Details
- **GET** `/steps/{id}/`
  - Permission: IsAuthenticated

#### Update Step
- **PUT** `/steps/{id}/`
  - Permission: IsAuthenticated

#### Delete Step
- **DELETE** `/steps/{id}/`
  - Permission: IsAuthenticated

#### Execute Step
- **POST** `/steps/{id}/execute/`
  - Description: Execute step
  - Permission: IsAuthenticated

#### Complete Step
- **POST** `/steps/{id}/complete/`
  - Description: Mark step as completed
  - Permission: IsAuthenticated

#### Skip Step
- **POST** `/steps/{id}/skip/`
  - Description: Skip step
  - Permission: IsAuthenticated

### Remediation Comment Endpoints

#### List Comments
- **GET** `/comments/`
  - Parameters: ticket (filter), workflow (filter), author (filter), comment_type (filter), search, page, page_size, ordering
  - Permission: IsAuthenticated

#### Create Comment
- **POST** `/comments/`
  - Body: content, ticket OR workflow, comment_type
  - Permission: IsAuthenticated
  - Side Effect: author set to current user

#### Get Comment Details
- **GET** `/comments/{id}/`
  - Permission: IsAuthenticated

#### Update Comment
- **PUT** `/comments/{id}/`
  - Permission: IsAuthenticated

#### Delete Comment
- **DELETE** `/comments/{id}/`
  - Permission: IsAuthenticated

### Remediation Template Endpoints

#### List Templates
- **GET** `/templates/`
  - Parameters: category (filter), is_active (filter), created_by (filter), search, page, page_size, ordering
  - Permission: IsAuthenticated

#### Create Template
- **POST** `/templates/`
  - Body: name, description, category, steps_config, is_active
  - Permission: IsAuthenticated

#### Get Template Details
- **GET** `/templates/{id}/`
  - Permission: IsAuthenticated

#### Update Template
- **PUT** `/templates/{id}/`
  - Permission: IsAuthenticated

#### Delete Template
- **DELETE** `/templates/{id}/`
  - Permission: IsAuthenticated

#### Clone Template
- **POST** `/templates/{id}/clone/`
  - Description: Clone template
  - Permission: IsAuthenticated

#### Apply Template
- **POST** `/templates/{id}/apply/`
  - Body: vulnerability_id (required)
  - Permission: IsAuthenticated
  - Side Effect: Increments usage_count

#### Template Categories
- **GET** `/templates/categories/`
  - Description: Get available template categories
  - Permission: IsAuthenticated

---

## Compliance Management (`/api/v1/compliance/`)

### Compliance Framework Endpoints

#### List Frameworks
- **GET** `/frameworks/`
  - Parameters: search, page, page_size, ordering
  - Permission: IsAuthenticated

#### Create Framework
- **POST** `/frameworks/`
  - Body: name, description, authority, version, is_active
  - Permission: IsAuthenticated

#### Get Framework Details
- **GET** `/frameworks/{id}/`
  - Permission: IsAuthenticated

#### Update Framework
- **PUT** `/frameworks/{id}/`
  - Permission: IsAuthenticated

#### Delete Framework
- **DELETE** `/frameworks/{id}/`
  - Permission: IsAuthenticated

#### Framework Controls
- **GET** `/frameworks/{id}/controls/`
  - Description: Get all controls for a framework
  - Permission: IsAuthenticated

#### Framework Assessments
- **GET** `/frameworks/{id}/assessments/`
  - Description: Get all assessments for a framework
  - Permission: IsAuthenticated

#### Framework Metrics
- **GET** `/frameworks/{id}/metrics/`
  - Description: Get latest metrics for a framework
  - Permission: IsAuthenticated

### Compliance Control Endpoints

#### List Controls
- **GET** `/controls/`
  - Parameters: search, page, page_size, ordering
  - Permission: IsAuthenticated

#### Create Control
- **POST** `/controls/`
  - Body: framework, control_id, title, description, criticality
  - Permission: IsAuthenticated

#### Get Control Details
- **GET** `/controls/{id}/`
  - Permission: IsAuthenticated

#### Update Control
- **PUT** `/controls/{id}/`
  - Permission: IsAuthenticated

#### Delete Control
- **DELETE** `/controls/{id}/`
  - Permission: IsAuthenticated

#### Control Results
- **GET** `/controls/{id}/results/`
  - Description: Get assessment results for a control
  - Permission: IsAuthenticated

#### Control Evidence
- **GET** `/controls/{id}/evidence/`
  - Description: Get evidence for a control
  - Permission: IsAuthenticated

### Compliance Assessment Endpoints

#### List Assessments
- **GET** `/assessments/`
  - Parameters: search, page, page_size, ordering
  - Permission: IsAuthenticated

#### Create Assessment
- **POST** `/assessments/`
  - Body: name, description, framework, assessment_type, scope_description, due_date, assets
  - Permission: IsAuthenticated

#### Get Assessment Details
- **GET** `/assessments/{id}/`
  - Permission: IsAuthenticated

#### Update Assessment
- **PUT** `/assessments/{id}/`
  - Permission: IsAuthenticated

#### Delete Assessment
- **DELETE** `/assessments/{id}/`
  - Permission: IsAuthenticated

#### Assessment Results
- **GET** `/assessments/{id}/results/`
  - Description: Get all results for an assessment
  - Permission: IsAuthenticated

#### Assessment Evidence
- **GET** `/assessments/{id}/evidence/`
  - Description: Get all evidence for an assessment
  - Permission: IsAuthenticated

#### Assessment Summary
- **GET** `/assessments/{id}/summary/`
  - Description: Get compliance summary (total_controls, compliant, non_compliant, partially_compliant, not_applicable, not_tested, compliance_percentage, risk levels)
  - Permission: IsAuthenticated

#### Overdue Assessments
- **GET** `/assessments/overdue/`
  - Description: Get overdue assessments
  - Permission: IsAuthenticated

### Compliance Evidence Endpoints

#### List Evidence
- **GET** `/evidence/`
  - Parameters: search, page, page_size, ordering
  - Permission: IsAuthenticated

#### Create Evidence
- **POST** `/evidence/`
  - Body: assessment, control, title, description, evidence_type, file
  - Content-Type: multipart/form-data
  - Permission: IsAuthenticated

#### Get Evidence Details
- **GET** `/evidence/{id}/`
  - Permission: IsAuthenticated

#### Update Evidence
- **PUT** `/evidence/{id}/`
  - Permission: IsAuthenticated

#### Delete Evidence
- **DELETE** `/evidence/{id}/`
  - Permission: IsAuthenticated

### Compliance Result Endpoints

#### List Results
- **GET** `/results/`
  - Parameters: search, page, page_size, ordering
  - Permission: IsAuthenticated

#### Create Result
- **POST** `/results/`
  - Body: assessment, control, status, risk_level, findings, recommendations
  - Permission: IsAuthenticated

#### Get Result Details
- **GET** `/results/{id}/`
  - Permission: IsAuthenticated

#### Update Result
- **PUT** `/results/{id}/`
  - Permission: IsAuthenticated

#### Delete Result
- **DELETE** `/results/{id}/`
  - Permission: IsAuthenticated

#### Non-Compliant Results
- **GET** `/results/non_compliant/`
  - Description: Get all non-compliant results
  - Permission: IsAuthenticated

#### High Risk Results
- **GET** `/results/high_risk/`
  - Description: Get high risk compliance results (risk_level in ['high', 'critical'])
  - Permission: IsAuthenticated

### Compliance Exception Endpoints

#### List Exceptions
- **GET** `/exceptions/`
  - Parameters: search, page, page_size, ordering
  - Permission: IsAuthenticated

#### Create Exception
- **POST** `/exceptions/`
  - Body: control, title, justification, valid_until, status
  - Permission: IsAuthenticated

#### Get Exception Details
- **GET** `/exceptions/{id}/`
  - Permission: IsAuthenticated

#### Update Exception
- **PUT** `/exceptions/{id}/`
  - Permission: IsAuthenticated

#### Delete Exception
- **DELETE** `/exceptions/{id}/`
  - Permission: IsAuthenticated

#### Pending Exceptions
- **GET** `/exceptions/pending/`
  - Description: Get pending exceptions
  - Permission: IsAuthenticated

#### Expiring Soon
- **GET** `/exceptions/expiring_soon/`
  - Description: Get exceptions expiring in next 30 days
  - Permission: IsAuthenticated

#### Needs Review
- **GET** `/exceptions/needs_review/`
  - Description: Get exceptions that need review
  - Permission: IsAuthenticated

### Compliance Metrics Endpoints

#### List Metrics
- **GET** `/metrics/`
  - Parameters: page, page_size, ordering
  - Permission: IsAuthenticated (Read-only)

#### Dashboard Metrics
- **GET** `/metrics/dashboard/`
  - Description: Get dashboard metrics for each active framework
  - Permission: IsAuthenticated
  - Response: framework name, compliance_percentage, total_controls, high_risk_findings, open_exceptions, last_updated

---

## Reporting & Analytics (`/api/v1/reports/`)

### Report Template Endpoints

#### List Templates
- **GET** `/templates/`
  - Parameters: search, page, page_size, ordering
  - Permission: IsAuthenticated

#### Create Template
- **POST** `/templates/`
  - Body: name, description, report_type, default_format, template_config
  - Permission: IsAuthenticated

#### Get Template Details
- **GET** `/templates/{id}/`
  - Permission: IsAuthenticated

#### Update Template
- **PUT** `/templates/{id}/`
  - Permission: IsAuthenticated

#### Delete Template
- **DELETE** `/templates/{id}/`
  - Permission: IsAuthenticated

#### Generate Report from Template
- **POST** `/templates/{id}/generate/`
  - Body: format (pdf, html, csv, excel), parameters, filters
  - Permission: IsAuthenticated
  - Status Code: 202 Accepted
  - Response: Report object with task ID

#### Template Reports
- **GET** `/templates/{id}/reports/`
  - Description: Get all reports generated from this template
  - Permission: IsAuthenticated

#### Template Metrics
- **GET** `/templates/{id}/metrics/`
  - Description: Get metrics for this template (last 30 days)
  - Permission: IsAuthenticated

### Report Schedule Endpoints

#### List Schedules
- **GET** `/schedules/`
  - Parameters: search, page, page_size, ordering
  - Permission: IsAuthenticated

#### Create Schedule
- **POST** `/schedules/`
  - Body: name, description, template, frequency (daily, weekly, monthly), next_run, status, format, parameters, filters
  - Permission: IsAuthenticated

#### Get Schedule Details
- **GET** `/schedules/{id}/`
  - Permission: IsAuthenticated

#### Update Schedule
- **PUT** `/schedules/{id}/`
  - Permission: IsAuthenticated

#### Delete Schedule
- **DELETE** `/schedules/{id}/`
  - Permission: IsAuthenticated

#### Run Schedule Now
- **POST** `/schedules/{id}/run_now/`
  - Description: Run a scheduled report immediately
  - Permission: IsAuthenticated
  - Status Code: 202 Accepted

#### Due Schedules
- **GET** `/schedules/due/`
  - Description: Get schedules that are due to run
  - Permission: IsAuthenticated

### Report Endpoints

#### List Reports
- **GET** `/reports/`
  - Parameters: search, page, page_size, ordering
  - Permission: IsAuthenticated

#### Get Report Details
- **GET** `/reports/{id}/`
  - Permission: IsAuthenticated

#### Delete Report
- **DELETE** `/reports/{id}/`
  - Permission: IsAuthenticated

#### Download Report
- **GET** `/reports/{id}/download/`
  - Description: Download a generated report file
  - Permission: IsAuthenticated
  - Response: File (pdf, html, csv, excel)
  - Status Code: 200 OK or 400 Bad Request if not ready

#### Recent Reports
- **GET** `/reports/recent/`
  - Description: Get recent reports (last 20)
  - Permission: IsAuthenticated

#### Failed Reports
- **GET** `/reports/failed/`
  - Description: Get failed reports
  - Permission: IsAuthenticated

### Dashboard Endpoints

#### List Dashboards
- **GET** `/dashboards/`
  - Parameters: search, page, page_size, ordering
  - Permission: IsAuthenticated

#### Create Dashboard
- **POST** `/dashboards/`
  - Body: name, description, dashboard_type, widgets_config, filters_config, is_public
  - Permission: IsAuthenticated

#### Get Dashboard Details
- **GET** `/dashboards/{id}/`
  - Permission: IsAuthenticated

#### Update Dashboard
- **PUT** `/dashboards/{id}/`
  - Permission: IsAuthenticated

#### Delete Dashboard
- **DELETE** `/dashboards/{id}/`
  - Permission: IsAuthenticated

#### Dashboard Data
- **GET** `/dashboards/{id}/data/`
  - Description: Get complete dashboard data with all widgets
  - Permission: IsAuthenticated
  - Response: dashboard info + widgets data + last_updated

#### Share Dashboard
- **POST** `/dashboards/{id}/share/`
  - Body: user_ids (list)
  - Permission: IsAuthenticated
  - Response: confirmation message

### Widget Endpoints

#### List Widgets
- **GET** `/widgets/`
  - Parameters: search, page, page_size, ordering
  - Permission: IsAuthenticated

#### Create Widget
- **POST** `/widgets/`
  - Body: name, description, widget_type, widget_config, filters
  - Permission: IsAuthenticated

#### Get Widget Details
- **GET** `/widgets/{id}/`
  - Permission: IsAuthenticated

#### Update Widget
- **PUT** `/widgets/{id}/`
  - Permission: IsAuthenticated

#### Delete Widget
- **DELETE** `/widgets/{id}/`
  - Permission: IsAuthenticated

#### Get Widget Data
- **GET** `/widgets/{id}/data/`
  - Parameters: filters (query params)
  - Permission: IsAuthenticated
  - Response: Widget data

#### Test Widget
- **POST** `/widgets/{id}/test/`
  - Body: filters
  - Permission: IsAuthenticated
  - Response: success/error status + data

### Report Metrics Endpoints

#### List Metrics
- **GET** `/metrics/`
  - Parameters: page, page_size, ordering
  - Permission: IsAuthenticated (Read-only)

#### Metrics Summary
- **GET** `/metrics/summary/`
  - Description: Get overall reporting metrics summary (last 30 days)
  - Permission: IsAuthenticated
  - Response: total_reports_generated, average_success_rate, most_popular_templates, total_storage_used_mb

### Alert Rule Endpoints

#### List Alert Rules
- **GET** `/alerts/`
  - Parameters: search, page, page_size, ordering
  - Permission: IsAuthenticated

#### Create Alert Rule
- **POST** `/alerts/`
  - Body: name, description, condition_type, threshold_value, is_active
  - Permission: IsAuthenticated

#### Get Alert Rule Details
- **GET** `/alerts/{id}/`
  - Permission: IsAuthenticated

#### Update Alert Rule
- **PUT** `/alerts/{id}/`
  - Permission: IsAuthenticated

#### Delete Alert Rule
- **DELETE** `/alerts/{id}/`
  - Permission: IsAuthenticated

#### Test Alert Rule
- **POST** `/alerts/{id}/test/`
  - Description: Test an alert rule
  - Permission: IsAuthenticated
  - Response: rule_triggered status, current_value, threshold_value

#### Check All Alert Rules
- **POST** `/alerts/check_all/`
  - Description: Check all active alert rules
  - Permission: IsAuthenticated
  - Status Code: 202 Accepted
  - Response: task_id

---

## Integrations (`/api/v1/integrations/`)

### External System Endpoints

#### List External Systems
- **GET** `/systems/`
  - Parameters: system_type (filter), status (filter), auth_type (filter), search, page, page_size, ordering
  - Permission: IsAuthenticated

#### Create External System
- **POST** `/systems/`
  - Body: name, description, vendor, system_type, auth_type, credentials, is_active
  - Permission: IsAuthenticated

#### Get System Details
- **GET** `/systems/{id}/`
  - Permission: IsAuthenticated

#### Update System
- **PUT** `/systems/{id}/`
  - Permission: IsAuthenticated

#### Delete System
- **DELETE** `/systems/{id}/`
  - Permission: IsAuthenticated

#### Test Connection
- **POST** `/systems/{id}/test_connection/`
  - Description: Test connection to external system
  - Permission: IsAuthenticated

#### Health Check
- **POST** `/systems/{id}/health_check/`
  - Description: Perform health check on external system
  - Permission: IsAuthenticated
  - Response: status, response_time_ms

#### Sync Status
- **GET** `/systems/{id}/sync_status/`
  - Description: Get synchronization status
  - Permission: IsAuthenticated

### Integration Mapping Endpoints

#### List Mappings
- **GET** `/mappings/`
  - Parameters: system (filter), guardian_entity (filter), sync_direction (filter), is_active (filter), page, page_size, ordering
  - Permission: IsAuthenticated

#### Create Mapping
- **POST** `/mappings/`
  - Body: system, guardian_entity, external_entity, field_mappings, sync_direction, is_active
  - Permission: IsAuthenticated

#### Get Mapping Details
- **GET** `/mappings/{id}/`
  - Permission: IsAuthenticated

#### Update Mapping
- **PUT** `/mappings/{id}/`
  - Permission: IsAuthenticated

#### Delete Mapping
- **DELETE** `/mappings/{id}/`
  - Permission: IsAuthenticated

#### Test Mapping
- **POST** `/mappings/{id}/test_mapping/`
  - Description: Test field mapping configuration
  - Permission: IsAuthenticated

#### Sync Now
- **POST** `/mappings/{id}/sync_now/`
  - Description: Trigger immediate synchronization
  - Permission: IsAuthenticated

### Sync Record Endpoints

#### List Sync Records
- **GET** `/sync-records/`
  - Parameters: system (filter), sync_type (filter), status (filter), entity_type (filter), page, page_size, ordering
  - Permission: IsAuthenticated

#### Get Sync Record Details
- **GET** `/sync-records/{id}/`
  - Permission: IsAuthenticated

#### Sync Statistics
- **GET** `/sync-records/sync_statistics/`
  - Description: Get synchronization statistics
  - Permission: IsAuthenticated
  - Response: total_syncs, successful_syncs, failed_syncs, sync_rate

#### Retry Sync
- **POST** `/sync-records/{id}/retry_sync/`
  - Description: Retry failed synchronization
  - Permission: IsAuthenticated

### Webhook Endpoint Endpoints

#### List Webhooks
- **GET** `/webhooks/`
  - Parameters: system (filter), is_active (filter), search, page, page_size, ordering
  - Permission: IsAuthenticated

#### Create Webhook
- **POST** `/webhooks/`
  - Body: name, description, system, url, events, secret, is_active
  - Permission: IsAuthenticated

#### Get Webhook Details
- **GET** `/webhooks/{id}/`
  - Permission: IsAuthenticated

#### Update Webhook
- **PUT** `/webhooks/{id}/`
  - Permission: IsAuthenticated

#### Delete Webhook
- **DELETE** `/webhooks/{id}/`
  - Permission: IsAuthenticated

#### Test Webhook
- **POST** `/webhooks/{id}/test_webhook/`
  - Description: Test webhook endpoint
  - Permission: IsAuthenticated

#### Trigger Webhook
- **POST** `/webhooks/{id}/trigger_webhook/`
  - Body: event_type
  - Description: Manually trigger webhook for testing
  - Permission: IsAuthenticated

### Integration Log Endpoints

#### List Integration Logs
- **GET** `/logs/`
  - Parameters: system (filter), operation_type (filter), log_level (filter), entity_type (filter), search, page, page_size, ordering
  - Permission: IsAuthenticated (Read-only)

#### Get Log Entry
- **GET** `/logs/{id}/`
  - Permission: IsAuthenticated (Read-only)

#### Error Summary
- **GET** `/logs/error_summary/`
  - Description: Get summary of integration errors
  - Permission: IsAuthenticated
  - Response: total_errors, error_rate, common_errors

#### Cleanup Logs
- **DELETE** `/logs/cleanup_logs/`
  - Parameters: older_than_days (default 30)
  - Description: Clean up old integration logs
  - Permission: IsAuthenticated

### Notification Channel Endpoints

#### List Notification Channels
- **GET** `/notifications/`
  - Parameters: channel_type (filter), is_active (filter), search, page, page_size, ordering
  - Permission: IsAuthenticated

#### Create Notification Channel
- **POST** `/notifications/`
  - Body: name, description, channel_type (email, slack, teams, webhook), channel_config, is_active, severity_levels
  - Permission: IsAuthenticated

#### Get Channel Details
- **GET** `/notifications/{id}/`
  - Permission: IsAuthenticated

#### Update Channel
- **PUT** `/notifications/{id}/`
  - Permission: IsAuthenticated

#### Delete Channel
- **DELETE** `/notifications/{id}/`
  - Permission: IsAuthenticated

#### Test Notification
- **POST** `/notifications/{id}/test_notification/`
  - Description: Test notification channel
  - Permission: IsAuthenticated

#### Send Notification
- **POST** `/notifications/{id}/send_notification/`
  - Body: message, severity (info, warning, error, critical)
  - Description: Send notification through this channel
  - Permission: IsAuthenticated

---

## Response Formats

### Success Response
All successful responses return JSON with appropriate HTTP status codes:
- `200 OK` - Successful GET, PUT, PATCH
- `201 Created` - Successful POST
- `202 Accepted` - Async operations (report generation, scan start)
- `204 No Content` - Successful DELETE

### Error Response
Error responses include details about the failure:
```json
{
    "error": "Validation Error",
    "message": "The provided data is invalid",
    "details": {
        "field_name": ["This field is required."]
    },
    "code": "VALIDATION_ERROR"
}
```

### Pagination
List endpoints support pagination:
```json
{
    "count": 1000,
    "next": "http://localhost:8000/api/v1/assets/?page=3",
    "previous": "http://localhost:8000/api/v1/assets/?page=1",
    "results": []
}
```

Default page size: 50, max: 100

---

## Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| VALIDATION_ERROR | 400 | Bad Request - Invalid data provided |
| UNAUTHORIZED | 401 | Unauthorized - Authentication required |
| FORBIDDEN | 403 | Forbidden - Insufficient permissions |
| NOT_FOUND | 404 | Not Found - Resource doesn't exist |
| CONFLICT | 409 | Conflict - Resource already exists |
| UNPROCESSABLE_ENTITY | 422 | Unprocessable Entity - Validation error |
| RATE_LIMIT_EXCEEDED | 429 | Too Many Requests - Rate limit exceeded |
| SERVER_ERROR | 500 | Internal Server Error - Server error |

---

## OpenAPI/Swagger Configuration

- Schema endpoint: `/api/schema/`
- Swagger UI: `/docs/`
- ReDoc: `/redoc/`

Title: "Open Security Guardian API"
Description: "Proactive Vulnerability Management Platform"
Version: 1.0.0

Tags:
- Assets: Asset inventory management
- Vulnerabilities: Vulnerability tracking and management
- Scanners: Vulnerability scanner integrations
- Remediation: Remediation workflow management
- Compliance: Compliance framework support
- Reports: Reporting and analytics

---

## Filtering and Searching

Most list endpoints support:

### Date Filters
```
GET /api/v1/vulnerabilities/?discovered_after=2025-06-01&discovered_before=2025-06-30
```

### Multiple Value Filters
```
GET /api/v1/vulnerabilities/?severity=critical,high&status=open
```

### Search
```
GET /api/v1/assets/?search=web-server
```

### Ordering
```
GET /api/v1/vulnerabilities/?ordering=-cvss_score,discovered_at
```

---

## Webhook Events

Available webhook event types:
- `vulnerability.created`
- `vulnerability.updated`
- `asset.created`
- `scan.completed`
- `compliance.assessment.completed`
- `remediation.ticket.created`

---

## Summary by Category

| Category | Endpoint Base | ViewSet Count | Total Endpoints |
|----------|---------------|---------------|-----------------|
| Assets | `/assets/` | 7 | 40+ |
| Vulnerabilities | `/vulnerabilities/` | 3 | 35+ |
| Scanners | `/scanners/` | 5 | 45+ |
| Remediation | `/remediation/` | 5 | 40+ |
| Compliance | `/compliance/` | 8 | 50+ |
| Reports | `/reports/` | 7 | 45+ |
| Integrations | `/integrations/` | 6 | 40+ |
| Core | `/` | 2 | 4 |
| **TOTAL** | **45 endpoints** | **43 ViewSets** | **280+ HTTP methods** |

