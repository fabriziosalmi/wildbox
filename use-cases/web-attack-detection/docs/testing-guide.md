# Testing Guide: Web Attack Detection

This guide helps you test the Wildbox log ingestion and analysis pipeline using the web attack detection use case.

## Before You Start

The sensor sends its events to the gateway with an API key of its own,
scoped to `data:ingest`, and you read them back through the gateway as a
member of the same team. Set up both as the
[use case README](../README.md#step-1b-create-the-sensors-account-and-api-key)
describes, then, from the Wildbox root:

```bash
# The sensor's key (data:ingest), read by the sensor
export SENSOR_DATA_LAKE_API_KEY=wsk_...
# The certificate the gateway generated, and a key of yours with the read scope
export WILDBOX_CA=$PWD/open-security-gateway/ssl/wildbox.crt
export H="X-API-Key: wsk_your_read_key"
```

Every `curl` below goes through the gateway, `https://localhost/api/v1/data`,
and shows your team's telemetry only.

## 🧪 Test Scenarios

### Scenario 1: Basic Log Ingestion

**Objective**: Verify that logs are being ingested into the Data Lake.

**Steps**:

1. Start Wildbox platform:

   ```bash
   cd /path/to/wildbox
   docker-compose up -d
   ```

2. Configure and start the sensor with sample logs:

   ```bash
   cd use-cases/web-attack-detection

   # Create test directory
   mkdir -p /tmp/wildbox-test

   # Copy sample logs
   cp sample-logs/nginx-access.log /tmp/wildbox-test/access.log
   ```

3. Update sensor config to point to test logs:

   ```yaml
   collection:
     log_forwarding: true

   log_sources:
     - name: nginx_access
       type: file
       path: /tmp/wildbox-test/access.log
       format: nginx
       read_from: beginning
   ```

   The sensor reads exactly this file. `read_from: beginning` also sends the
   sample lines already in it when the sensor starts; with the default,
   `end`, only lines written afterwards are sent. When it starts, the sensor
   logs `Log source 'nginx_access': reading /tmp/wildbox-test/access.log from
   its beginning`, or a warning naming the source if it cannot read the file.

   `generate_logs.py`, used in the scenarios below, rewrites its output file
   at every run. The sensor notices that the file was truncated and reads it
   again from its beginning, so each run's lines are sent once.

4. Start the sensor and verify ingestion:

   ```bash
   # Check telemetry stats
   curl --cacert "$WILDBOX_CA" -H "$H" "https://localhost/api/v1/data/telemetry/stats" | jq

   # Expected output: events_by_type counts security_event; each log
   # event carries the tag log.nginx_access
   ```

**Expected Result**: Events appear in telemetry stats.

---

### Scenario 2: Real-Time Log Generation

**Objective**: Test real-time log ingestion with simulated ongoing attacks.

**Steps**:

1. Generate logs in real-time mode:

   ```bash
   cd use-cases/web-attack-detection/sample-logs

   # Generate 1 log per second for 60 seconds
   python3 generate_logs.py \
     --output /tmp/wildbox-test/access.log \
     --realtime \
     --duration 60 \
     --attack-rate 0.5
   ```

2. Monitor ingestion in another terminal:

   ```bash
   # Watch stats update
   watch -n 2 "curl -s --cacert '$WILDBOX_CA' -H '$H' https://localhost/api/v1/data/telemetry/stats | jq"
   ```

**Expected Result**: Event count increases in real-time.

---

### Scenario 3: Attack Pattern Detection

**Objective**: Verify different attack patterns are properly ingested and tagged.

**Steps**:

1. Generate logs with high attack rate:

   ```bash
   python3 generate_logs.py \
     --output /tmp/wildbox-test/access.log \
     --count 500 \
     --attack-rate 0.8
   ```

2. Query for specific attack patterns:

   ```bash
   # Get all events
   curl --cacert "$WILDBOX_CA" -H "$H" "https://localhost/api/v1/data/telemetry/events?limit=100" | jq

   # Log events: type security_event, log source as a tag
   curl --cacert "$WILDBOX_CA" -H "$H" "https://localhost/api/v1/data/telemetry/events?event_type=security_event&limit=100" | \
     jq '[.[] | select(.tags | index("log.nginx_access"))]'
   ```

3. Analyze event data:

   ```bash
   # Look for SQL injection patterns in event_data
   curl --cacert "$WILDBOX_CA" -H "$H" "https://localhost/api/v1/data/telemetry/events?limit=500" | \
     jq '.[] | select(.event_data.data.request | contains("OR")) | {timestamp, ip: .event_data.data.client_ip, request: .event_data.data.request}'
   ```

**Expected Result**: Different attack types are visible in the event data.

---

### Scenario 4: Performance Testing

**Objective**: Test sensor performance under high log volume.

**Steps**:

1. Generate a large number of logs:

   ```bash
   python3 generate_logs.py \
     --output /tmp/wildbox-test/access.log \
     --count 10000 \
     --attack-rate 0.3
   ```

2. Monitor sensor resource usage:

   ```bash
   # If using Docker
   docker stats sensor

   # Check sensor logs for performance issues
   docker-compose logs sensor | grep -i error
   ```

3. Verify all events were ingested:

   ```bash
   curl --cacert "$WILDBOX_CA" -H "$H" "https://localhost/api/v1/data/telemetry/stats" | jq .total_events
   ```

**Expected Result**: All 10,000 events ingested without errors or high resource usage.

---

### Scenario 5: IP-Based Threat Tracking

**Objective**: Track repeated attacks from the same IP address.

**Steps**:

1. Generate logs (attackers will be from 10.0.0.100-119):

   ```bash
   python3 generate_logs.py \
     --output /tmp/wildbox-test/access.log \
     --count 1000 \
     --attack-rate 0.5
   ```

2. Query events by specific attacker IP:

   ```bash
   # Get all events from a specific IP
   curl --cacert "$WILDBOX_CA" -H "$H" "https://localhost/api/v1/data/telemetry/events?limit=1000" | \
     jq '[.[] | select(.event_data.data.client_ip == "10.0.0.100")] | length'
   ```

3. Identify top attacking IPs:

   ```bash
   # Count events per IP (requires jq processing)
   curl --cacert "$WILDBOX_CA" -H "$H" "https://localhost/api/v1/data/telemetry/events?limit=1000" | \
     jq -r '.[].event_data.data.client_ip' | sort | uniq -c | sort -rn | head -10
   ```

**Expected Result**: Attacker IPs (10.0.0.100-119) show higher event counts.

---

### Scenario 6: Time-Range Queries

**Objective**: Query events within specific time windows.

**Steps**:

1. Generate logs spread over time:

   ```bash
   python3 generate_logs.py \
     --output /tmp/wildbox-test/access.log \
     --count 1000
   ```

2. Query recent events:

   ```bash
   # Events from last hour
   START_TIME=$(date -u -v-1H +"%Y-%m-%dT%H:%M:%SZ")
   curl --cacert "$WILDBOX_CA" -H "$H" "https://localhost/api/v1/data/telemetry/events?start_time=${START_TIME}&limit=100" | jq
   ```

3. Check stats for different time windows:

   ```bash
   # Last 1 hour
   curl --cacert "$WILDBOX_CA" -H "$H" "https://localhost/api/v1/data/telemetry/stats?hours=1" | jq

   # Last 24 hours
   curl --cacert "$WILDBOX_CA" -H "$H" "https://localhost/api/v1/data/telemetry/stats?hours=24" | jq
   ```

**Expected Result**: Events are properly filtered by time range.

---

## 🔍 Validation Checklist

### ✅ Sensor Health

- [ ] Sensor service is running
- [ ] No errors in sensor logs
- [ ] Sensor appears in sensors list: `curl --cacert "$WILDBOX_CA" -H "$H" "https://localhost/api/v1/data/sensors"`
- [ ] Memory usage is within limits (< 128MB by default)

### ✅ Data Ingestion

- [ ] Events are visible in telemetry API
- [ ] Event count increases with new logs
- [ ] Event timestamps are accurate
- [ ] Log format is correctly parsed

### ✅ Event Data Quality

- [ ] Client IP is extracted correctly
- [ ] Request path/query is captured
- [ ] Status codes are present
- [ ] User agents are preserved
- [ ] Attack patterns are in event_data

### ✅ API Functionality

- [ ] Health endpoint returns 200
- [ ] Stats endpoint shows metrics
- [ ] Events endpoint returns data
- [ ] Pagination works (offset/limit)
- [ ] Time filtering works

---

## 🐛 Troubleshooting Tests

### Test Fails: No Events Ingested

**Diagnosis**:

```bash
# Check sensor logs
docker-compose logs sensor

# Verify log file exists and is readable
ls -la /tmp/wildbox-test/access.log

# Test the connection to the gateway with the sensor's key
docker-compose exec sensor python main.py --config /etc/security-sensor/config.yaml --test-connection
```

**Common Fixes**:

- Ensure log file path is correct in config: the sensor's log has a
  `Log source '<name>'` line for each source it reads, and a warning with
  the reason for each file it does not
- With `read_from: end` (the default) only lines written after the sensor
  started are sent
- Check the gateway is running: `docker-compose ps gateway`
- Set `SENSOR_DATA_LAKE_API_KEY` to an identity API key with the
  `data:ingest` scope; without one the sensor logs that forwarding is
  disabled
- A 401 in the sensor's log: the key is invalid, expired or revoked; a 403
  `insufficient_scope`: it lacks `data:ingest`; a certificate error:
  `data_lake.ca_bundle` is not the gateway's certificate
- Read the events as a member of the sensor's team: other teams see none
- Check file permissions

### Test Fails: Events Missing Data

**Diagnosis**:

```bash
# Check raw event structure
curl --cacert "$WILDBOX_CA" -H "$H" "https://localhost/api/v1/data/telemetry/events?limit=1" | jq '.[0]'

# Verify log format matches nginx format
head -5 /tmp/wildbox-test/access.log
```

**Common Fixes**:

- Ensure log format in config matches actual logs
- Check log_forwarder.py parsing logic
- Verify no corruption in log files

### Test Fails: High Resource Usage

**Diagnosis**:

```bash
# Check resource limits
docker stats sensor

# Review performance config
grep -A 10 "performance:" sensor-config/config.yaml
```

**Common Fixes**:

- Reduce batch_size in config
- Increase flush_interval
- Reduce max_queue_size
- Lower worker_threads

---

## 📊 Test Metrics

Track these metrics during testing:

| Metric | Target | Command |
| -------- | -------- | --------- |
| Events ingested | 100% of generated | `curl --cacert "$WILDBOX_CA" -H "$H" "https://localhost/api/v1/data/telemetry/stats"` |
| Memory usage | < 128 MB | `docker stats sensor` |
| CPU usage | < 5% | `docker stats sensor` |
| Ingestion latency | < 5 seconds | Compare log timestamp to ingested_at |
| API response time | < 500ms | `time curl --cacert "$WILDBOX_CA" -H "$H" "https://localhost/api/v1/data/telemetry/events"` |

---

## 🎯 Success Criteria

A successful test demonstrates:

1. ✅ Logs are continuously ingested without drops
2. ✅ Attack patterns are identifiable in event data
3. ✅ Resource usage stays within configured limits
4. ✅ API queries return accurate data
5. ✅ No errors in sensor or data lake logs
6. ✅ Events can be filtered by time, sensor, and type

---

## 📝 Test Report Template

Use this template to document your test results:

```markdown
## Test Report: Web Attack Detection

**Date**: YYYY-MM-DD
**Tester**: Your Name
**Wildbox Version**: x.x.x

### Environment
- OS:
- Docker Version:
- Total RAM:
- Log Volume:

### Test Results

| Scenario | Status | Notes |
|----------|--------|-------|
| Basic Log Ingestion | ✅/❌ | |
| Real-Time Generation | ✅/❌ | |
| Attack Pattern Detection | ✅/❌ | |
| Performance Testing | ✅/❌ | |
| IP-Based Tracking | ✅/❌ | |
| Time-Range Queries | ✅/❌ | |

### Performance Metrics
- Events ingested: X
- Peak memory usage: X MB
- Peak CPU usage: X%
- Average ingestion latency: X seconds

### Issues Found
1. Issue description
2. Issue description

### Recommendations
1. Recommendation
2. Recommendation
```

---

## 🔗 Related Documentation

- [Main README](../README.md)
- [Attack Patterns Reference](attack-patterns.md)
- [Wildbox Data Lake API](../../../docs/api/data/endpoints.md)
