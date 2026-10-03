# Open Security Data quick start

This guide starts the data service inside the Wildbox stack, seeds its
sources and queries it through the gateway. See [README.md](README.md) for the
architecture, the full route list and configuration.

## 1. Start the services

From the repository root, after generating secrets as described in the root
[README](../README.md):

```bash
docker compose up -d data data-scheduler gateway
docker compose ps data data-scheduler
```

The gateway depends on every backend it routes to, so this starts the rest of
the stack too.

The `data` container applies the database migrations at startup. Its port,
8002, is published on `127.0.0.1` only; clients go through the gateway on
HTTPS port 443.

## 2. Add sources

The database starts without sources. Add the default set and check it:

```bash
docker compose exec data python manage.py sources add-defaults
docker compose exec data python manage.py sources list
```

The default sources are Malware Domain List, PhishTank, Feodo Tracker,
AbuseIPDB Blacklist and URLVoid Reputation. AbuseIPDB and URLVoid need an API
key in their source configuration before they collect anything.

Enable, disable or run a source once:

```bash
docker compose exec data python manage.py sources disable "Malware Domain List"
docker compose exec data python manage.py sources enable "Malware Domain List"
docker compose exec data python manage.py sources test "Feodo Tracker"
```

`data-scheduler` runs each enabled source when its collection interval
elapses; follow it with `docker compose logs -f data-scheduler`.

## 3. Query the API

Get a token as shown in the root [README](../README.md), then call the
service through the gateway. `/api/v1/data/<path>` maps to the service's
`/api/v1/<path>`:

```bash
CA=open-security-gateway/ssl/wildbox.crt
AUTH="Authorization: Bearer $TOKEN"

# Health and statistics
curl --cacert "$CA" -H "$AUTH" https://localhost/api/v1/data/health
curl --cacert "$CA" -H "$AUTH" https://localhost/api/v1/data/stats

# Search
curl --cacert "$CA" -H "$AUTH" \
  "https://localhost/api/v1/data/indicators/search?indicator_type=domain&threat_types=phishing"

# Lookups
curl --cacert "$CA" -H "$AUTH" https://localhost/api/v1/data/ips/203.0.113.10
curl --cacert "$CA" -H "$AUTH" https://localhost/api/v1/data/domains/example.com
curl --cacert "$CA" -H "$AUTH" \
  https://localhost/api/v1/data/hashes/d41d8cd98f00b204e9800998ecf8427e

# Bulk lookup
curl --cacert "$CA" -H "$AUTH" -H "Content-Type: application/json" \
  -X POST https://localhost/api/v1/data/indicators/lookup \
  -d '{"indicators": [
        {"indicator_type": "ip_address", "value": "203.0.113.10"},
        {"indicator_type": "domain", "value": "example.com"}
      ]}'

# Indicators seen in the last hour, as NDJSON
curl --cacert "$CA" -H "$AUTH" \
  "https://localhost/api/v1/data/feeds/realtime?since_minutes=60"
```

An API key works in place of the token: send `X-API-Key: <key>` instead of
the `Authorization` header.

## Sensor telemetry

The sensor posts telemetry to `https://<gateway>/api/v1/data/ingest` with an
identity API key scoped to `data:ingest`, and the service stores it under that
key's team. Any member of the team reads it:

```bash
curl --cacert "$CA" -H "$AUTH" \
  "https://localhost/api/v1/data/telemetry/events?limit=10"
```

Setting up the sensor's member and key is described in
[the sensor README](../open-security-sensor/README.md#sending-telemetry-to-wildbox).
