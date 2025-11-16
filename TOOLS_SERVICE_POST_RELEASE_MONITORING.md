# Tools Service - Post-Release Monitoring Checklist

**Service:** Wildbox Security Tools
**Version:** 1.0.0-beta
**Release Date:** 2025-11-16
**Monitoring Period:** First 7 days (then weekly)

---

## 📊 **DAILY MONITORING CHECKLIST** (Days 1-7)

### Day 1 (Launch Day) - Every 2 Hours

- [ ] **Service Health**
  ```bash
  docker-compose ps
  curl -s http://localhost:8000/health | jq
  ```
  Expected: All containers `Up (healthy)`, health response `200 OK`

- [ ] **Container Logs** (check for errors)
  ```bash
  docker logs open-security-tools --tail 100 | grep -i error
  docker logs open-security-tools --tail 100 | grep -i warning
  ```
  Expected: No critical errors, warnings acceptable if documented

- [ ] **Authentication Test**
  ```bash
  # Gateway auth
  curl -s http://localhost/api/v1/tools/hash_generator/info \
    -H "X-API-Key: $API_KEY" | jq '.display_name'

  # Direct auth (legacy)
  curl -s http://localhost:8000/api/tools/hash_generator/info \
    -H "X-API-Key: $API_KEY" | jq '.display_name'
  ```
  Expected: Both return `"Hash Generator"`

- [ ] **Tool Execution Test** (3 random tools)
  ```bash
  # Test 1: Password Generator
  curl -s -X POST http://localhost:8000/api/tools/password_generator \
    -H "X-API-Key: $API_KEY" \
    -H "Content-Type: application/json" \
    -d '{"length": 16, "include_uppercase": true, "include_numbers": true}' \
    | jq '.success'

  # Test 2: WHOIS Lookup
  curl -s -X POST http://localhost:8000/api/tools/whois_lookup \
    -H "X-API-Key: $API_KEY" \
    -H "Content-Type: application/json" \
    -d '{"domain": "google.com", "timeout": 10}' \
    | jq '.success'

  # Test 3: Port Scanner
  curl -s -X POST http://localhost:8000/api/tools/port_scanner \
    -H "X-API-Key: $API_KEY" \
    -H "Content-Type: application/json" \
    -d '{"target": "127.0.0.1", "ports": [80, 443, 8000], "timeout": 5}' \
    | jq '.results | length'
  ```
  Expected: All return `true` or valid results

- [ ] **Resource Usage**
  ```bash
  docker stats --no-stream open-security-tools open-security-tools-worker
  ```
  Expected: Memory < 512MB, CPU < 50%

- [ ] **Redis Status**
  ```bash
  docker exec -it open-security-tools-redis redis-cli PING
  docker exec -it open-security-tools-redis redis-cli INFO stats | grep total_commands_processed
  ```
  Expected: `PONG`, command count increasing

---

### Days 2-7 - Twice Daily (Morning & Evening)

- [ ] **Service Health** (same as Day 1)
- [ ] **Error Rate Analysis**
  ```bash
  # Count errors in last 24h
  docker logs open-security-tools --since 24h 2>&1 | grep -c "ERROR"
  ```
  Expected: < 10 errors/day (excluding known schema mismatches)

- [ ] **Performance Check**
  ```bash
  # Average response time (check logs)
  docker logs open-security-tools --tail 1000 | grep "execution_time" | jq -s 'map(.execution_time) | add/length'
  ```
  Expected: < 2 seconds average

- [ ] **Unique Tool Usage**
  ```bash
  # Tools being used
  docker logs open-security-tools --since 24h | grep "Executing tool" | awk '{print $NF}' | sort | uniq -c | sort -rn | head -10
  ```
  Expected: Diverse tool usage, no single tool > 80% of requests

---

## 🚨 **CRITICAL ALERTS** (Immediate Action Required)

### Alert 1: Service Down
**Symptom:**
```bash
docker-compose ps | grep -i "exit\|restarting"
```
**Action:**
1. Check logs: `docker logs open-security-tools --tail 200`
2. Check disk space: `df -h`
3. Restart service: `docker-compose restart open-security-tools`
4. If persists: `docker-compose down && docker-compose up -d`
5. Notify team if downtime > 5 minutes

### Alert 2: Memory Leak
**Symptom:**
```bash
docker stats --no-stream open-security-tools | awk '{print $4}' | grep -E "[8-9][0-9]%|100%"
```
**Action:**
1. Identify culprit: `docker exec open-security-tools ps aux --sort=-%mem | head -10`
2. Restart service: `docker-compose restart open-security-tools`
3. Monitor for recurrence
4. If recurring: Review tool execution logs, identify problematic tools

### Alert 3: Authentication Failures
**Symptom:**
```bash
docker logs open-security-tools --since 1h | grep -c "401\|403" | awk '$1 > 100 {print "ALERT: " $1 " auth failures"}'
```
**Action:**
1. Check if API key leaked: Review access logs for unusual IPs
2. Rotate API key if confirmed leak
3. Check gateway logs: `docker logs open-security-gateway --tail 100`
4. Verify authentication configuration in `.env`

### Alert 4: Suspicious Activity (Command Injection Attempts)
**Symptom:**
```bash
docker logs open-security-tools --since 1h | grep -E "\$\(|;|&&|\|nc|\/etc\/passwd|cat /|ls -la" | wc -l
```
**Action:**
1. **DO NOT PANIC** - We tested for this!
2. Verify payloads were blocked:
   ```bash
   docker logs open-security-tools --since 1h | grep -A 5 "validation_failed\|Validation Error"
   ```
3. Document attack patterns for analysis
4. Check if attacks succeeded (shouldn't):
   ```bash
   docker logs open-security-tools | grep -E "ls -la|whoami|cat /etc/passwd"
   ```
5. If ANY commands executed: **IMMEDIATE ROLLBACK**

---

## 📈 **WEEKLY METRICS REVIEW** (Days 7, 14, 21, 30)

### Tool Usage Statistics

```bash
# Generate weekly tool usage report
cat << 'EOF' > weekly_tool_report.sh
#!/bin/bash
echo "=== Weekly Tool Usage Report ==="
echo "Period: Last 7 days"
echo ""
echo "Top 10 Tools:"
docker logs open-security-tools --since 7d | grep "Executing tool" | awk '{print $NF}' | sort | uniq -c | sort -rn | head -10
echo ""
echo "Total Executions:"
docker logs open-security-tools --since 7d | grep -c "Executing tool"
echo ""
echo "Error Rate:"
TOTAL=$(docker logs open-security-tools --since 7d | grep -c "Executing tool")
ERRORS=$(docker logs open-security-tools --since 7d | grep -c "ERROR")
echo "Errors: $ERRORS / Total: $TOTAL"
echo "Rate: $(echo "scale=2; $ERRORS * 100 / $TOTAL" | bc)%"
EOF
chmod +x weekly_tool_report.sh
./weekly_tool_report.sh
```

### Performance Metrics

- [ ] **Average Response Time**
  - Target: < 2 seconds
  - Source: Application logs `execution_time` field

- [ ] **P95/P99 Response Time**
  - Target: P95 < 5s, P99 < 10s
  - Source: Aggregate from logs

- [ ] **Timeout Rate**
  - Target: < 5%
  - Count: `grep "408\|timeout" | wc -l`

### Availability Metrics

- [ ] **Uptime Percentage**
  - Target: > 99.5% (3.6 minutes downtime/week)
  - Monitor: `docker logs open-security-tools --since 7d | grep "startup"`

- [ ] **Failed Health Checks**
  - Target: 0
  - Check: `docker inspect open-security-tools | jq '.[0].State.Health.FailingStreak'`

### Security Metrics

- [ ] **Authentication Failures**
  - Target: < 50/day
  - Check: `grep "401\|403" | wc -l`

- [ ] **Suspicious Payloads Blocked**
  - Target: 100% blocked
  - Verify: No evidence of command execution in logs

---

## 🐛 **KNOWN ISSUES MONITORING**

### Schema Validation Failures (~7/55 tools)

**Tools Affected:**
- jwt_decoder
- base64_tool
- hash_generator
- url_analyzer
- header_analyzer
- ip_geolocation
- dns_enumerator

**Symptom:**
```json
{
  "error": {
    "code": 422,
    "message": "Input validation failed: ..."
  }
}
```

**Monitoring:**
```bash
# Count schema validation errors
docker logs open-security-tools --since 24h | grep "422" | wc -l
```

**Expected:** < 20/day (normal for tools with schema issues)
**Alert if:** > 100/day (new issue)

**Action:** Document and log for v1.1.0 fix

---

## 🔄 **ROLLBACK PROCEDURE** (If Critical Issues Found)

### When to Rollback

Trigger immediate rollback if:
1. Command injection successful (commands executed)
2. Service downtime > 30 minutes
3. Data breach or credential leak
4. Memory/CPU exhaustion causing system instability

### Rollback Steps

```bash
# 1. Stop current deployment
docker-compose down

# 2. Checkout previous stable commit
git log --oneline -10  # Find last stable commit
git checkout <previous-commit-hash>

# 3. Rebuild and restart
docker-compose build
docker-compose up -d

# 4. Verify rollback
docker-compose ps
curl http://localhost:8000/health

# 5. Notify team and users
echo "Rollback completed at $(date)" >> rollback.log

# 6. Document incident
# Create incident report in docs/incidents/
```

### Post-Rollback

1. **Root Cause Analysis:** Review logs, identify issue
2. **Fix Development:** Create hotfix branch
3. **Testing:** Reproduce issue, verify fix
4. **Re-deploy:** Only after thorough testing

---

## 📞 **ESCALATION MATRIX**

| Severity | Response Time | Action | Contact |
|----------|---------------|--------|---------|
| **P0 - Critical** | Immediate | Service down, security breach | On-call engineer + Team lead |
| **P1 - High** | < 1 hour | Performance degradation, auth issues | On-call engineer |
| **P2 - Medium** | < 4 hours | Feature bugs, schema errors | Team Slack channel |
| **P3 - Low** | < 24 hours | Documentation, minor bugs | GitHub Issues |

### P0 Examples
- Command injection successful
- All tools returning 500 errors
- Authentication bypass discovered
- Service unreachable

### P1 Examples
- Memory leak (> 80% usage)
- Response times > 10 seconds
- 50% of tools failing
- Gateway authentication issues

---

## ✅ **SUCCESS CRITERIA** (Beta → GA)

### Required for v1.0.0 GA Release

- [ ] **Stability:** 7 days uptime > 99.5% with no critical incidents
- [ ] **Performance:** P95 response time < 5 seconds
- [ ] **Security:** 0 command injection vulnerabilities (maintained)
- [ ] **Usage:** At least 10 unique beta testers providing feedback
- [ ] **Bug Resolution:** All P0/P1 bugs resolved, P2 documented for v1.1.0
- [ ] **Schema Issues:** At least 3/7 schema validation issues fixed
- [ ] **Documentation:** All known issues documented in README
- [ ] **Monitoring:** Automated alerts configured for critical metrics

### Nice-to-Have for GA

- [ ] 25+ tools tested by beta users
- [ ] 5+ community contributions (bug reports, PRs, etc.)
- [ ] Integration examples with popular tools (curl, Python, Postman)
- [ ] Performance benchmarks published

---

## 📝 **MONITORING LOG TEMPLATE**

```markdown
## Monitoring Log - [DATE]

**Checked by:** [NAME]
**Time:** [HH:MM UTC]

### Health Check
- [ ] Service Status: UP / DOWN
- [ ] Container Health: HEALTHY / UNHEALTHY
- [ ] Error Count (24h): [NUMBER]
- [ ] Memory Usage: [PERCENTAGE]
- [ ] CPU Usage: [PERCENTAGE]

### Tool Tests
- [ ] password_generator: PASS / FAIL
- [ ] whois_lookup: PASS / FAIL
- [ ] port_scanner: PASS / FAIL

### Issues Found
[Describe any issues, errors, or anomalies]

### Actions Taken
[Describe any corrective actions]

### Notes
[Any additional observations]
```

---

## 🎯 **MONITORING AUTOMATION** (Optional but Recommended)

### Create Monitoring Script

```bash
cat << 'EOF' > monitor_tools_service.sh
#!/bin/bash

# Wildbox Tools Service Monitoring Script
# Run: */15 * * * * /path/to/monitor_tools_service.sh >> /var/log/wildbox_monitor.log 2>&1

API_KEY="replace-this-with-a-secure-random-string-32-chars-long"
ALERT_EMAIL="ops@wildbox.io"  # Optional

echo "=== Monitoring Check: $(date) ==="

# 1. Health Check
HEALTH=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/health)
if [ "$HEALTH" != "200" ]; then
  echo "ALERT: Health check failed (HTTP $HEALTH)"
  # Send alert email (optional)
  # echo "Health check failed" | mail -s "Wildbox Alert" $ALERT_EMAIL
fi

# 2. Test Tool Execution
PASSWORD=$(curl -s -X POST http://localhost:8000/api/tools/password_generator \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"length": 16}' | jq -r '.password')

if [ -z "$PASSWORD" ] || [ "$PASSWORD" == "null" ]; then
  echo "ALERT: Tool execution failed (password_generator)"
fi

# 3. Resource Check
MEM=$(docker stats --no-stream open-security-tools --format "{{.MemPerc}}" | sed 's/%//')
if (( $(echo "$MEM > 80" | bc -l) )); then
  echo "WARNING: High memory usage ($MEM%)"
fi

# 4. Error Rate
ERRORS=$(docker logs open-security-tools --since 15m | grep -c "ERROR")
if [ "$ERRORS" -gt 10 ]; then
  echo "WARNING: High error rate ($ERRORS errors in 15 min)"
fi

echo "Check complete. Health: $HEALTH, Mem: $MEM%, Errors: $ERRORS"
echo ""
EOF

chmod +x monitor_tools_service.sh

# Add to crontab (run every 15 minutes)
# crontab -e
# */15 * * * * /path/to/monitor_tools_service.sh >> /var/log/wildbox_monitor.log 2>&1
```

---

**This monitoring plan ensures the Tools service remains stable, secure, and performant throughout the beta period and beyond.**

**Questions? Check the main README or open a GitHub Discussion.**
