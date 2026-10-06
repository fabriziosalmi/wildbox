# Observability Roadmap

> **Partly superseded.** Phase 1 (Prometheus metrics) and the Alertmanager of
> phase 5 are done, though not in the way this plan proposed; the sections
> below say what exists. Phases 2 to 4 remain plans. For the services and
> ports that run today see <https://www.wildbox.io/guides/ports/>.

**Status:** Phase 1 and phase 5.1 done; phases 2 to 4 planned  
**Priority:** MEDIUM

## Current State

**Working:**

- Service health checks (`/health` endpoints, wired into Compose
  `healthcheck` entries)
- `/metrics` in Prometheus exposition format on identity, tools, data,
  responder, CSPM and agents, through `install_observability()` in
  `open-security-shared/observability.py` (request count and latency by
  method, path template and status, plus an `X-Request-ID` correlation header)
- Guardian serves its own `/metrics/` view (`apps/core/views.py`, on when
  `PROMETHEUS_ENABLED` is true, the default), but Prometheus does not scrape it
- A Prometheus server in the `monitoring` Compose profile, with scrape targets
  in `monitoring/prometheus.yml` and alert rules in `monitoring/alert_rules.yml`
- An Alertmanager in the same profile, which Prometheus sends firing alerts
  to. Its shipped configuration notifies nobody; e-mail and webhook examples
  are in `monitoring/examples/` (see the
  [deployment guide](https://www.wildbox.io/guides/deployment/#7-monitoring))

**Missing:**

- **Guardian and gateway scraping** (not in `monitoring/prometheus.yml`)
- **Worker metrics**: `guardian-worker`, `cspm-worker` and the data
  scheduler export nothing, so scans and feed collection have no alert.
  `tools-worker` exports nothing either, but counts its asynchronous runs in
  Redis, and the tools API exports the counts
  (`open-security-tools/app/async_metrics.py`)
- **Grafana dashboards**
- **Distributed tracing**: there is none. No service creates a span, no
  image installs OpenTelemetry and no Compose file runs a trace collector.
  What crosses a service boundary today is the `X-Request-ID` header
- **Log aggregation** (ELK/Loki)

## Phase 1: Prometheus Metrics (Done)

### 1.1 Metrics Endpoints

The FastAPI services do not use `prometheus-fastapi-instrumentator`; they call
`install_observability(app, ...)` from the shared package, which exposes
`/metrics` with `prometheus_client`. If `prometheus_client` is missing the
middleware keeps only the request ID, so a service still starts.

Guardian (Django) does not use `django-prometheus`; it has a `MetricsView`
that returns `prometheus_client.generate_latest()`.

The gateway exposes no Prometheus metrics.

### 1.2 Prometheus Service

Start it with the `monitoring` profile:

```bash
docker compose --profile monitoring up -d
```

The `prometheus` service in `docker-compose.yml` runs
`prom/prometheus:v3.13.4`, publishes the UI on `127.0.0.1:9090` only, and
mounts `monitoring/prometheus.yml` and `monitoring/alert_rules.yml`.
`monitoring/prometheus.yml` scrapes every 30 seconds, in one job named
`wildbox-services`:

```yaml
scrape_configs:
  - job_name: wildbox-services
    metrics_path: /metrics
    static_configs:
      - targets:
          - open-security-identity:8001
          - open-security-tools:8000
          - open-security-data:8002
          - open-security-responder:8018
          - open-security-cspm:8019
          - open-security-agents:8006
```

There are no PostgreSQL or Redis exporters.


### 1.3 Key Metrics to Track

**HTTP Metrics:**

- Request count by endpoint, method, status code
- Request duration (histogram)
- Request size / response size

**Application Metrics:**

- Active API keys
- Authentication attempts (success/failure)
- Rate limit hits
- Tools executed (by type)
- Vulnerabilities scanned
- Threats detected

**Infrastructure Metrics:**

- Database connection pool usage
- Redis cache hit/miss ratio
- Gateway request queue depth
- Service restart count

## Phase 2: Grafana Dashboards

### 2.1 Add Grafana Service

```yaml
  grafana:
    image: grafana/grafana:10.2.3
    container_name: wildbox-grafana
    restart: unless-stopped
    ports:
      - "3001:3000"  # Avoid conflict with dashboard on 3000
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_ADMIN_PASSWORD}
      - GF_USERS_ALLOW_SIGN_UP=false
    volumes:
      - grafana-data:/var/lib/grafana
      - ./monitoring/grafana/provisioning:/etc/grafana/provisioning
    networks:
      - wildbox-network
    depends_on:
      - prometheus

volumes:
  grafana-data:
```

### 2.2 Pre-Built Dashboards

**Service Overview Dashboard:**

- Service health matrix
- Request rate per service
- Error rate per service
- Average response time
- Top 10 slowest endpoints

**Security Operations Dashboard:**

- Threats detected over time
- Vulnerabilities by severity
- Authentication failures
- Rate limit violations
- API key usage patterns

**Infrastructure Dashboard:**

- CPU/Memory usage per container
- Database query performance
- Redis cache efficiency
- Gateway throughput
- Network I/O

## Phase 3: Distributed Tracing

Not started, and nothing in the repository implements it. The shared
package used to have a `tracing.py` module and a `tracing` extra; the
module imported the Jaeger Thrift exporter, whose last release (1.21.0) does
not import under a current OpenTelemetry SDK, no image installed the extra,
and `install_observability()` only logged at every start-up that tracing was
not initialized. Module, extra and the `enable_tracing` argument were
removed.

### 3.1 What tracing needs

**For request flow visibility:**

- Browser → Gateway → Identity → Database
- Track latency at each hop
- Identify bottlenecks

**To build it:**

- an exporter that is maintained: OTLP
  (`opentelemetry-exporter-otlp-proto-http`), not the Jaeger Thrift exporter
- the OpenTelemetry packages locked in the `requirements.in` of each service
  that traces, behind an extra of `open-security-shared`
  (see the [dependency guide](DEPENDENCY_MANAGEMENT_GUIDE.md))
- a collector that receives OTLP (Jaeger or Tempo) in the `monitoring`
  Compose profile
- trace context forwarded by the gateway, next to `X-Request-ID`

## Phase 4: Log Aggregation

### 4.1 Centralized Logging

**Options:**

- **Grafana Loki** (lightweight, integrates with Grafana)
- **ELK Stack** (Elasticsearch, Logstash, Kibana)
- **Fluentd** (log shipper)

**Log shipping from Docker:**

```yaml
services:
  identity:
    logging:
      driver: "fluentd"
      options:
        fluentd-address: "localhost:24224"
        tag: "wildbox.identity"
```

## Phase 5: Alerting

### 5.1 Prometheus AlertManager

Done. The `monitoring` profile runs `prom/alertmanager:v0.34.1`,
`monitoring/prometheus.yml` has an `alerting` section that names it, and
`monitoring/alert_rules.yml` holds `WildboxServiceDown`,
`WildboxHighErrorRate`, `WildboxSyncToolFailureRate`,
`WildboxAsyncToolFailureRate`, `WildboxAsyncToolTasksNotConsumed`,
`WildboxAsyncToolMetricsUnreadable`, `WildboxAlertmanagerDown` and
`WildboxAlertNotificationsFailing`, with unit tests in
`monitoring/alert_rules.test.yml`. What each alert measures, and how to
configure a receiver, is in the
[deployment guide](https://www.wildbox.io/guides/deployment/#7-monitoring).
The original proposal follows; its rules were not adopted as written (the
metrics they name, `http_requests_total` and `pg_stat_activity_count`, are
not exported).

**Proposed rules (original plan):**

```yaml
groups:
  - name: wildbox
    interval: 30s
    rules:
      - alert: ServiceDown
        expr: up == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Service {{ $labels.job }} is down"

      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.05
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High error rate on {{ $labels.job }}"

      - alert: DatabaseConnectionsHigh
        expr: pg_stat_activity_count > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "PostgreSQL connection pool near limit"
```

## Integration with Dashboard

### Update Frontend to Fetch Real Metrics

**src/lib/metrics-client.ts:**

```typescript
export class MetricsClient {
  async getSystemHealth() {
    // Query Prometheus API
    const response = await fetch('http://prometheus:9090/api/v1/query', {
      method: 'POST',
      body: JSON.stringify({
        query: 'up{job="identity"}'
      })
    })
    
    const data = await response.json()
    return {
      uptime: parseUptime(data),
      responseTime: await this.getResponseTime(),
      errorRate: await this.getErrorRate()
    }
  }

  async getResponseTime() {
    const response = await fetch('http://prometheus:9090/api/v1/query', {
      method: 'POST',
      body: JSON.stringify({
        query: 'histogram_quantile(0.95, http_request_duration_seconds_bucket)'
      })
    })
    // ... parse response
  }
}
```

**Update dashboard/page.tsx:**

```typescript
const systemHealth = await metricsClient.getSystemHealth()
// No more nulls!
```

## Timeline

| Phase | Effort | Timeline | Dependencies |
| ------- | -------- | ---------- | -------------- |
| 1. Prometheus | Done | Done | None |
| 2. Grafana | 1 week | Q1 2026 | Phase 1 |
| 3. Tracing | 2 weeks | Q2 2026 | Phase 1 |
| 4. Logging | 1 week | Q2 2026 | None |
| 5. Alerting | 1 week | Q2 2026 | Phase 1, 2 |
| **Total** | **7 weeks** | **Q1-Q2 2026** | |

## Estimated Costs

**Self-Hosted (Recommended):**

- $0/month (runs in existing Docker Compose)
- +200MB RAM per container (Prometheus, Grafana)
- +10GB disk for 30-day metrics retention

**Cloud (Alternative):**

- Grafana Cloud: $0-$50/month (depending on volume)
- Datadog: $15/host/month
- New Relic: $25/user/month

## Success Metrics

After Phase 1 & 2 completion:

- [x] Services expose a `/metrics` endpoint
- [ ] Prometheus scraping all services (today: six services every 30s; guardian and the gateway are not scraped)
- [ ] Grafana dashboards show real-time data
- [ ] Dashboard UI displays actual metrics (no N/A)
- [ ] 95th percentile response time < 200ms
- [ ] Error rate < 1%
- [ ] Service uptime > 99.5%

## References

- [Prometheus FastAPI Instrumentator](https://github.com/trallnag/prometheus-fastapi-instrumentator)
- [Django Prometheus](https://github.com/korfuri/django-prometheus)
- [Grafana Provisioning](https://grafana.com/docs/grafana/latest/administration/provisioning/)
- [OpenTelemetry Python](https://opentelemetry.io/docs/instrumentation/python/)

---

**Document Owner:** Platform Team  
**Last Updated:** October 6, 2026
