# Data Service API

**Gateway path**: `https://<host>/api/v1/data/...` (proxied to the service's
`/api/v1/...`)
**Health**: `https://<host>/api/v1/data/health` (proxied to the service's
`/health`)
**Authentication**: through the gateway only, with a JWT bearer token or an
API key sent as `X-API-Key`. There is no anonymous access.

Host names, IDs and keys in the examples are placeholders.

## Overview

The data service stores threat intelligence indicators (IP addresses,
domains, URLs, file hashes and other types) collected from public feeds, and
the telemetry that security sensors send to it. It answers searches and
lookups over the indicators, a real-time feed, dashboard figures, and
queries over telemetry and sensors.

Indicators and sources are team-scoped: a caller sees the global ones
(collected from the public feeds, with no team) and those of its own team.
Telemetry events and sensors belong to one team only, with no global rows;
see [Telemetry](#telemetry).

## Table of Contents

- [Authentication](#authentication)
- [Endpoint Summary](#endpoint-summary)
- [Health](#health)
- [Indicators](#indicators)
- [Intelligence Lookups](#intelligence-lookups)
- [Sources, Feeds and Statistics](#sources-feeds-and-statistics)
- [Telemetry](#telemetry)
- [Errors](#errors)
- [Rate Limits](#rate-limits)
- [Examples](#examples)

## Authentication

Every request goes through the gateway. The gateway validates the
credential with the identity service and forwards the caller to the data
service as `X-Wildbox-User-ID`, `X-Wildbox-Team-ID` and `X-Wildbox-Role`
headers, with how the caller authenticated (`X-Wildbox-Auth-Type`: `session`
or `api_key`), an API key's scopes (`X-Wildbox-Scopes`) and the
`X-Gateway-Secret` proof of origin. The data service refuses, with 403, a
request without the user and team headers, with a wrong secret, or without
`X-Wildbox-Auth-Type` (`GATEWAY_AUTH_TYPE_REQUIRED` in the error's `details`)
(`open-security-data/app/auth.py`, which uses
`open_security_shared/gateway_auth.py`), so its own port is not an entry
point. It reads no API key of its own: the `API_KEY_REQUIRED` and
`API_KEY_HEADER` settings were removed because nothing read them.

```bash
CA=open-security-gateway/ssl/wildbox.crt
TOKEN=$(curl -s --cacert "$CA" -X POST https://<host>/auth/jwt/login \
  --data-urlencode "username=$ADMIN_EMAIL" \
  --data-urlencode "password=$ADMIN_PASSWORD" | jq -r .access_token)

curl -s --cacert "$CA" "https://<host>/api/v1/data/indicators/search?q=example.com" \
  -H "Authorization: Bearer $TOKEN"
```

An API key (`POST /api/v1/identity/api-keys`, or
`POST /api/v1/identity/teams/{team_id}/api-keys` for a team key) is sent as
`X-API-Key: <key>`. A key with scopes needs `read` for `GET` requests and
`write` for `POST` requests on `/api/v1/data/...`, including the read-only
`POST /indicators/lookup`; the gateway answers 403 `insufficient_scope`
otherwise. `POST /ingest` needs `data:ingest`, `data:write` or `write`; a
key with `data:ingest` alone can call that route and nothing else, which is
the key a sensor is given. A JWT is not limited by scopes. The service
checks the same scopes again on what the gateway forwards about the key, so
a request the gateway should not have let through answers 403 with
`INSUFFICIENT_SCOPE` in the error's `details`. The
[Authentication and sessions guide](../../guides/authentication.md) covers
both credentials.

## Endpoint Summary

Paths are relative to `https://<host>/api/v1/data`.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Service health |
| `GET` | `/indicators/search` | Search indicators |
| `GET` | `/indicators/{indicator_id}` | One indicator with its enrichment |
| `POST` | `/indicators/lookup` | Look up many indicators at once |
| `GET` | `/ips/{ip_address}` | Indicators for an IP address |
| `GET` | `/domains/{domain}` | Indicators for a domain |
| `GET` | `/hashes/{file_hash}` | Indicators for a file hash |
| `GET` | `/sources` | Threat intelligence sources |
| `GET` | `/feeds/realtime` | Recent indicators as NDJSON |
| `GET` | `/stats` | Indicator and source counts |
| `GET` | `/dashboard/threat-intel` | Dashboard figures |
| `POST` | `/ingest` | Ingest a batch of telemetry events |
| `GET` | `/telemetry/events` | Query telemetry events |
| `GET` | `/telemetry/stats` | Telemetry counts |
| `GET` | `/sensors` | Sensors that sent telemetry |
| `GET` | `/sensors/{sensor_id}` | One sensor |

## Health

### GET /api/v1/data/health

Authenticated like every other data route; the gateway forwards it to the
service's `/health`.

```bash
curl -s --cacert "$CA" https://<host>/api/v1/data/health \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200 OK)**:

```json
{
  "status": "healthy",
  "timestamp": "2026-10-03T10:00:00.000000+00:00"
}
```

## Indicators

An indicator in a response has these fields:

| Field | Description |
| --- | --- |
| `id` | Indicator UUID |
| `indicator_type` | `ip_address`, `domain`, `url`, `file_hash`, `email`, `certificate`, `asn` or `vulnerability` |
| `value`, `normalized_value` | The value as collected and its normalized form |
| `threat_types` | List, for example `malware`, `phishing`, `botnet` |
| `confidence` | `low`, `medium`, `high` or `verified` |
| `severity` | 1 to 10 |
| `description`, `tags` | Free text and a list of tags |
| `first_seen`, `last_seen`, `expires_at` | Timestamps |
| `active` | Whether the indicator is active |
| `source_id` | UUID of the source that provided it |
| `indicator_metadata` | Additional metadata (an object) |
| `created_at`, `updated_at` | Record timestamps |

### GET /api/v1/data/indicators/search

Search the indicators the caller can see, most recently seen first.

| Query parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `q` | string | | Case-insensitive substring of the value, the normalized value or the description |
| `indicator_type` | string | | Exact type, for example `ip_address` |
| `threat_types` | string, repeatable | | Indicators that have every threat type given |
| `confidence` | string | | `low`, `medium`, `high` or `verified` |
| `min_severity`, `max_severity` | integer | | 1 to 10 |
| `source_id` | string | | Source UUID |
| `since` | datetime | | Indicators last seen at or after this time |
| `active_only` | boolean | `true` | Only active indicators |
| `limit` | integer | 100 | 1 to 10000 |
| `offset` | integer | 0 | Pagination offset |

```bash
curl -s --cacert "$CA" \
  "https://<host>/api/v1/data/indicators/search?indicator_type=ip_address&threat_types=malware&min_severity=7&limit=50" \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200 OK)**:

```json
{
  "indicators": [
    {
      "id": "0b8d3b1e-5d0f-4c55-9a43-3f2a7b0c9e11",
      "indicator_type": "ip_address",
      "value": "192.0.2.1",
      "normalized_value": "192.0.2.1",
      "threat_types": ["malware"],
      "confidence": "high",
      "severity": 8,
      "description": "Known malicious IP",
      "tags": ["botnet"],
      "first_seen": "2026-10-01T10:00:00Z",
      "last_seen": "2026-10-03T09:00:00Z",
      "expires_at": null,
      "active": true,
      "source_id": "6a0f8e52-1c3b-4b7e-8d55-2e9f0a1b2c3d",
      "indicator_metadata": {},
      "created_at": "2026-10-01T10:00:00Z",
      "updated_at": "2026-10-03T09:00:00Z"
    }
  ],
  "total": 1,
  "limit": 50,
  "offset": 0,
  "query_time": "2026-10-03T10:00:00Z"
}
```

`total` counts every match before `limit` and `offset` apply.

### GET /api/v1/data/indicators/{indicator_id}

One indicator the caller can see, with `enrichment` (type-specific data, an
empty object when there is none) and `raw_data` (the data as the source
provided it).

`indicator_id` must be a lowercase UUID; anything else answers 422.
**404** (`Indicator not found`) for an unknown indicator or one of another
team.

| `indicator_type` | `enrichment` fields |
| --- | --- |
| `ip_address` | `ip_version`, `asn`, `asn_organization`, `country_code`, `city`, `coordinates` |
| `domain` | `tld`, `subdomain`, `apex_domain`, `registrar`, `creation_date`, `expiration_date`, `dns_resolves`, `ip_addresses`, `mx_records`, `ns_records` |
| `file_hash` | `hash_type`, `file_name`, `file_size`, `file_type`, `mime_type`, `malware_family`, `signature_names`, `detection_ratio` |

The service fills what it can derive from the value alone: `ip_version` for an
IP address; `tld`, `subdomain` and `apex_domain` for a domain; `hash_type` for a
file hash. Nothing in the service looks up or writes the other fields, so they
are empty on every indicator it collects.

### POST /api/v1/data/indicators/lookup

Look up many indicators in one request. Read-only, although it is a `POST`.

```bash
curl -s --cacert "$CA" -X POST https://<host>/api/v1/data/indicators/lookup \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "indicators": [
      {"indicator_type": "ip_address", "value": "192.0.2.1"},
      {"indicator_type": "domain", "value": "example.com"}
    ]
  }'
```

`indicator_type` must be one of the indicator types listed above (422
otherwise). A value matches an active indicator of that type by its value
or its normalized value (lowercase, trimmed).

**Response (200 OK)**:

```json
{
  "results": [
    {"indicator_type": "ip_address", "value": "192.0.2.1", "found": true, "matches": [{"id": "0b8d3b1e-5d0f-4c55-9a43-3f2a7b0c9e11", "...": "..."}]},
    {"indicator_type": "domain", "value": "example.com", "found": false, "matches": []}
  ],
  "total_queried": 2,
  "total_found": 1,
  "query_time": "2026-10-03T10:00:00Z"
}
```

At most 1000 items: more answers 422, and 400 when the service's
`MAX_BATCH_SIZE` is set lower than 1000.

## Intelligence Lookups

Each lookup returns the active indicators of one type matching the value,
the enrichment of the first match, and the query time. **404** when the
caller can see no matching indicator.

### GET /api/v1/data/ips/{ip_address}

```bash
curl -s --cacert "$CA" https://<host>/api/v1/data/ips/192.0.2.1 \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200 OK)**:

```json
{
  "ip_address": "192.0.2.1",
  "threat_count": 1,
  "indicators": [{"id": "0b8d3b1e-5d0f-4c55-9a43-3f2a7b0c9e11", "...": "..."}],
  "enrichment": {
    "asn": null,
    "asn_organization": null,
    "country_code": null,
    "city": null,
    "coordinates": null
  },
  "query_time": "2026-10-03T10:00:00Z"
}
```

`enrichment` is `null` when the indicator has no IP row. Its fields are `null`
for an indicator the service collected (nothing looks them up); `coordinates`,
when both are stored, is `{"latitude": "<string>", "longitude": "<string>"}`.

### GET /api/v1/data/domains/{domain}

Same shape, with `domain` in place of `ip_address`. The domain is matched as
given and lowercased. `enrichment` fields: `tld`, `registrar`,
`creation_date`, `expiration_date`, `ip_addresses`, `mx_records`,
`ns_records`.

### GET /api/v1/data/hashes/{file_hash}

Same shape, with `file_hash` in place of `ip_address`. The hash is matched
as given and lowercased. `enrichment` fields: `hash_type`, `file_name`,
`file_size`, `file_type`, `malware_family`, `signature_names`,
`detection_ratio`.

## Sources, Feeds and Statistics

### GET /api/v1/data/sources

The sources the caller can see, by name.

| Query parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled_only` | boolean | `true` | Only enabled sources |

Each item has `id`, `name`, `description`, `source_type`, `enabled`,
`status`, `last_collection`, `collection_count` and `error_count`.

### GET /api/v1/data/feeds/realtime

Recent indicators as newline-delimited JSON (`application/x-ndjson`), most
recently seen first, at most 1000. The response is computed once and ends;
it is not a long-lived stream.

| Query parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `indicator_types` | string, repeatable | | Only these types |
| `threat_types` | string, repeatable | | Indicators that have every threat type given |
| `min_severity` | integer | | 1 to 10 |
| `since_minutes` | integer | 60 | Indicators last seen in this many minutes, 1 to 1440 |

```bash
curl -s --cacert "$CA" \
  "https://<host>/api/v1/data/feeds/realtime?since_minutes=60&min_severity=7" \
  -H "Authorization: Bearer $TOKEN"
```

Each line holds `id`, `indicator_type`, `value`, `threat_types`,
`confidence`, `severity`, `description`, `tags`, `first_seen`, `last_seen`
and `source_id`.

### GET /api/v1/data/stats

```json
{
  "total_indicators": 1520,
  "indicator_types": {"ip_address": 900, "domain": 420, "url": 200},
  "total_sources": 12,
  "active_sources": 10,
  "recent_collections": 24,
  "timestamp": "2026-10-03T10:00:00Z"
}
```

Every figure covers what the caller can see: its team's rows and the
global ones (a source or an indicator without a team). Indicator counts are
of active indicators. `recent_collections` counts the collection runs
started in the last 24 hours of the sources the caller can see; it counted
every team's runs before
[#755](https://github.com/fabriziosalmi/wildbox/issues/755).

### GET /api/v1/data/dashboard/threat-intel

The figures of the dashboard's threat intelligence card, over the caller's
team and the global sources and indicators.

```json
{
  "total_feeds": 12,
  "active_feeds": 10,
  "last_updated": "2026-10-03T09:00:00+00:00",
  "new_indicators": 35,
  "trends_change": 12.5
}
```

| Field | Description |
| --- | --- |
| `total_feeds`, `active_feeds` | Sources, and enabled sources |
| `last_updated` | End of the last completed collection run of a visible source; `null` when none has completed |
| `new_indicators` | Active indicators created in the last 24 hours |
| `trends_change` | Percent change of `new_indicators` from the 24 hours before, one decimal; `null` when that earlier period had none |

## Telemetry

Telemetry belongs to a team: the team of the credential it was sent with.
Every telemetry route reads or writes the caller's team's events and sensors
only; unlike indicators there are no global rows. Rows stored before
telemetry had a team (`team_id` empty) are visible to no team;
[UPGRADING.md](https://github.com/fabriziosalmi/wildbox/blob/main/UPGRADING.md) gives the SQL to count, assign or
delete them.

### POST /api/v1/data/ingest

Ingest a batch of telemetry events. The events and the sensor's record are
stored under the caller's team; the body carries no team, and a team named
in it is ignored. A sensor that the team does not know yet is registered
from its first event. A sensor's `sensor_id` is unique within its team, so
two teams can use the same name without touching each other's records.

The sensor calls this route through the gateway with an identity API key of
a team member, sent as `X-API-Key`, scoped to `data:ingest`
(`SENSOR_DATA_LAKE_API_KEY`); the
[sensor README](https://github.com/fabriziosalmi/wildbox/blob/main/open-security-sensor/README.md#sending-telemetry-to-wildbox)
and the [deployment guide](../../guides/deployment.md) cover the setup. Any
other credential that passes the gateway works too.

```bash
curl -s --cacert "$CA" -X POST https://<host>/api/v1/data/ingest \
  -H "X-API-Key: $SENSOR_DATA_LAKE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "batch_id": "batch-001",
    "events": [
      {
        "sensor_id": "sensor-001",
        "event_type": "process_event",
        "timestamp": "2026-10-03T09:59:00Z",
        "source_host": "workstation-01",
        "event_data": {"process_name": "cmd.exe"},
        "severity": 5,
        "tags": ["process"]
      }
    ]
  }'
```

| Event field | Required | Description |
| --- | --- | --- |
| `sensor_id` | Yes | Sensor identifier, at most 255 characters |
| `event_type` | Yes | `process_event`, `network_connection`, `file_change`, `user_event`, `system_inventory`, `authentication` or `security_event` |
| `timestamp` | Yes | When the event happened |
| `event_data` | Yes | Event-specific object |
| `source_host` | No | Host the event came from, at most 255 characters |
| `raw_data` | No | Raw event as a string |
| `severity` | No | 1 to 10 (default 1) |
| `tags` | No | List of strings |

`batch_id` is optional; the service generates one when it is absent.

**Response (200 OK)**:

```json
{
  "batch_id": "batch-001",
  "events_received": 1,
  "events_ingested": 1,
  "errors": [],
  "ingested_at": "2026-10-03T10:00:00Z"
}
```

A batch is stored in one transaction: every event of it, or none
([#755](https://github.com/fabriziosalmi/wildbox/issues/755)). A 200 means
all of them, so `events_ingested` equals `events_received` and `errors` is
empty; the field is kept for clients that read it. Every other answer means
nothing was stored, and has the error body of the services:

| Status | Meaning | What to do with the batch |
| --- | --- | --- |
| 422, `type: ValidationError` | An event is not valid. `details` lists each error with its place, `["body", "events", <index>, <field>]` | Remove or correct that event; the others can be sent |
| 422, `details.code: BATCH_NOT_STORABLE` | The database refuses a value the validation let through | The same, without knowing which event: send the batch in halves |
| 400 | More events than `MAX_BATCH_SIZE` (more than 1000 answers 422) | Send fewer |
| 503, with `Retry-After: 5` | The database did not take the batch, for a reason that may pass | Send it again |
| 500 | A fault of the service | Send it again |

`sensor_id`, `source_host` and `raw_data` may not contain a NUL character,
which PostgreSQL cannot store in a text column; `event_data` and `tags` may.
Before #755 a batch with such an event was answered 200 with
`events_ingested: 0`, a `sensor_id` longer than a column was a 503 for as
long as it was sent, and an event the service failed on was left out of a
batch that was otherwise stored.

The sensor acts on these answers as the table says: it keeps a batch
answered 5xx and sends it again, and splits a batch answered 422 or 400 in
halves until the event the service refuses is alone, which it drops.
`tests/shared/ingest_answer_vectors.json` holds the answers for the tests
of both sides. Through the gateway, an invalid, expired or revoked key
answers 401 and a key without an ingest scope 403 `insufficient_scope`.

### GET /api/v1/data/telemetry/events

The caller's team's events, newest first.

| Query parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `sensor_id` | string | | One sensor |
| `event_type` | string | | One event type |
| `start_time`, `end_time` | datetime | | Event time range, inclusive |
| `limit` | integer | 100 | At most 1000 |
| `offset` | integer | 0 | Pagination offset |

Each event has the ingest fields plus `id`, `ingested_at`, `processed` and
`processed_at`.

### GET /api/v1/data/telemetry/stats

| Query parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `sensor_id` | string | | One sensor |
| `hours` | integer | 24 | Time window |

```json
{
  "time_window_hours": 24,
  "total_events": 120,
  "active_sensors": 2,
  "events_by_type": {"process_event": 80, "network_connection": 40},
  "query_time": "2026-10-03T10:00:00+00:00"
}
```

Counts cover the caller's team only. `active_sensors` counts the team's
active sensors seen within the window, whatever `sensor_id` is.

### GET /api/v1/data/sensors

The caller's team's sensors, most recently seen first.

| Query parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `active_only` | boolean | `true` | Only active sensors |

Each sensor has `id`, `sensor_id`, `hostname`, `platform`,
`sensor_version`, `config`, `first_seen`, `last_seen`, `active`,
`total_events` and `last_event_at`.

### GET /api/v1/data/sensors/{sensor_id}

One of the caller's team's sensors by its `sensor_id`. **404**
(`Sensor not found`) when the team has none by that name, including when
another team has one.

## Errors

The gateway answers its own refusals with
`{"error": "<code>", "message": "..."}`:

| Status | `error` | Cause |
| --- | --- | --- |
| 401 | `authentication_required` | No bearer token and no `X-API-Key` |
| 401 | `invalid_token` | Token or key invalid, expired or revoked |
| 403 | `insufficient_scope` | API key without the required scope |
| 403 | `team_membership_ended` | The user was removed from the team the credential is for |
| 403 | `PASSWORD_CHANGE_REQUIRED` | The account must change its initial password first |
| 429 | `rate_limit_exceeded` | Per-team limit; see [Rate Limits](#rate-limits) |
| 503 | `service_unavailable` | The gateway could not reach the identity service |

The data service answers in the shape every Wildbox service uses:

```json
{
  "error": {
    "code": 404,
    "message": "Indicator not found",
    "type": "HTTPException",
    "request_id": "6f1c2d..."
  }
}
```

| Status | Cause |
| --- | --- |
| 400 | Batch larger than `MAX_BATCH_SIZE` |
| 404 | Indicator, IP address, domain, hash or sensor not found (or not visible to the caller) |
| 422 | Invalid parameter or body; `details` lists the errors as `{"type", "loc", "msg"}`, without the value that was refused |
| 500 | Server error |
| 503 | Telemetry batch not stored; send it again |

## Rate Limits

The data service applies no rate limit of its own: its
`RATE_LIMIT_ENABLED`, `RATE_LIMIT_REQUESTS` and `RATE_LIMIT_WINDOW`
settings are read by nothing. The gateway limits each team to
`RATE_LIMIT_PER_HOUR` requests per hour (default 10000), enforced in fixed
60-second windows of one sixtieth of that (166 by default), and reports the
current window in `X-RateLimit-Limit`, `X-RateLimit-Remaining` and
`X-RateLimit-Reset`, with `X-RateLimit-Policy: <per hour>;w=3600`. Past the
limit it answers 429 with `Retry-After`. `RATE_LIMIT_PER_HOUR` must be a
whole number from 1 to 1000000000; any other value stops the gateway at
startup. The gateway also limits each client IP to 100 requests per second with a
burst of 10 (`GATEWAY_RATE_LIMIT_PER_SECOND`, 100 unless the operator
changed it).

## Examples

### Check a List of IP Addresses

```bash
CA=open-security-gateway/ssl/wildbox.crt

for ip in 192.0.2.1 198.51.100.7; do
  curl -s --cacert "$CA" "https://<host>/api/v1/data/ips/$ip" \
    -H "X-API-Key: $WILDBOX_API_KEY" | jq '{ip_address, threat_count}'
done
```

### Read the Last Hour of High-Severity Indicators

```bash
curl -s --cacert "$CA" \
  "https://<host>/api/v1/data/feeds/realtime?since_minutes=60&min_severity=7" \
  -H "X-API-Key: $WILDBOX_API_KEY" \
  | jq -c '{indicator_type, value, severity}'
```

## Related Documentation

- [Authentication and sessions](../../guides/authentication.md) - Tokens and API keys
- [Security Policy](../../security/policy.md) - Authentication requirements
- [API Reference Hub](../../api-reference.html) - All service endpoints
- [Guardian Service API](../guardian/endpoints.md) - Vulnerability management
- [Agents Service API](../agents/endpoints.md) - Threat analysis
