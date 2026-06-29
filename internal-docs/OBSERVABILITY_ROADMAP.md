# Observability Roadmap

**Status:** PLANNED  
**Priority:** MEDIUM  
**Timeline:** Q1 2026

## Current State

**Working:**
- Service health checks (`/health` endpoints)
- Basic uptime monitoring via health checks
- Service status indicators in admin UI
- Docker Compose service orchestration

**Missing:**
- **Prometheus metrics scraping**
- **Grafana dashboards**
- **Distributed tracing** (Jaeger/Tempo)
- **Application Performance Monitoring (APM)**
- **Log aggregation** (ELK/Loki)
- **Alerting** (PagerDuty/OpsGenie)

## Phase 1: Prometheus Metrics (Priority)

### 1.1 Add Prometheus Exporters

**FastAPI Services** (identity, tools, agents, responder, cspm):
```python
# pip install prometheus-fastapi-instrumentator
from prometheus_fastapi_instrumentator import Instrumentator

app = FastAPI()
Instrumentator().instrument(app).expose(app)  # Exposes /metrics endpoint
```

**Django Services** (guardian, data):
```python
# pip install django-prometheus
INSTALLED_APPS = [
    'django_prometheus',
    # ...
]

MIDDLEWARE = [
    'django_prometheus.middleware.PrometheusBeforeMiddleware',
    # ... other middleware ...
    'django_prometheus.middleware.PrometheusAfterMiddleware',
]
```

**Nginx/OpenResty Gateway**:
```nginx
# Add to nginx.conf
server {
    location /metrics {
        stub_status on;
        access_log off;
        allow 172.16.0.0/12;  # Docker network
        deny all;
    }
}
```

### 1.2 Add Prometheus Service

**docker-compose.yml addition:**
```yaml
  prometheus:
    image: prom/prometheus:v2.48.0
    container_name: wildbox-prometheus
    restart: unless-stopped
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--storage.tsdb.retention.time=30d'
    networks:
      - wildbox-network

volumes:
  prometheus-data:
```

**monitoring/prometheus/prometheus.yml:**
```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'gateway'
    static_configs:
      - targets: ['gateway:80']
    metrics_path: '/metrics'

  - job_name: 'identity'
    static_configs:
      - targets: ['identity:8001']
    metrics_path: '/metrics'

  - job_name: 'tools'
    static_configs:
      - targets: ['tools:8000']
    metrics_path: '/metrics'

  - job_name: 'data'
    static_configs:
      - targets: ['data:8002']
    metrics_path: '/metrics'

  - job_name: 'guardian'
    static_configs:
      - targets: ['guardian:8013']
    metrics_path: '/metrics'

  - job_name: 'responder'
    static_configs:
      - targets: ['responder:8018']
    metrics_path: '/metrics'

  - job_name: 'agents'
    static_configs:
      - targets: ['agents:8006']
    metrics_path: '/metrics'

  - job_name: 'cspm'
    static_configs:
      - targets: ['cspm:8019']
    metrics_path: '/metrics'

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres-exporter:9187']

  - job_name: 'redis'
    static_configs:
      - targets: ['redis-exporter:9121']
```

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

### 3.1 Add Jaeger/Tempo

**For request flow visibility:**
- Browser → Gateway → Identity → Database
- Track latency at each hop
- Identify bottlenecks

**OpenTelemetry instrumentation:**
```python
from opentelemetry import trace
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

provider = TracerProvider()
jaeger_exporter = JaegerExporter(
    agent_host_name="jaeger",
    agent_port=6831,
)
provider.add_span_processor(BatchSpanProcessor(jaeger_exporter))
trace.set_tracer_provider(provider)
```

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

**monitoring/prometheus/alerts.yml:**
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
|-------|--------|----------|--------------|
| 1. Prometheus | 2 weeks | Q1 2026 | None |
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
- [ ] All services expose `/metrics` endpoint
- [ ] Prometheus scraping all services every 15s
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
**Last Updated:** November 23, 2025  
**Next Review:** January 2026
