# Wildbox Test Suite - Improvement Action Plan

**Generated**: 16 November 2025
**Based On**: Coverage Analysis Report + Baseline Test Results
**Current Status**: 43.1% success rate, 35-40% functional coverage
**Target**: 70% success rate, 60% functional coverage (90 days)

---

## Executive Summary

This action plan provides a prioritized roadmap to improve Wildbox's test suite from 43% to 70% success rate over 90 days, organized into 4 phases:

1. **Quick Wins** (1 week) - Fix existing failures → 55-60% success
2. **Foundation** (3 weeks) - Add critical missing tests → 60-65% success
3. **Expansion** (4 weeks) - Comprehensive coverage → 65-70% success
4. **Excellence** (ongoing) - Maintain and optimize → 70%+ success

**ROI Estimate**: High - Each phase delivers immediate value and unblocks subsequent work.

---

## Phase 1: Quick Wins (Week 1)

**Goal**: Fix existing test failures with minimal effort
**Target Success Rate**: 55-60% (from 43%)
**Estimated Effort**: 16-20 hours

### Task 1.1: Complete Pattern 3 - Authentication Configuration

**Priority**: CRITICAL ⚡
**Effort**: 4-6 hours
**Impact**: +7 tests (Identity service)

**Steps:**
1. Verify/create default admin user in Identity service
   ```bash
   # Check if admin exists
   docker-compose exec postgres psql -U wildbox -d identity \
     -c "SELECT email, is_active FROM users WHERE email='admin@wildbox.local';"

   # If not exists, create via API or direct DB insert
   ```

2. Create `tests/.env` configuration file:
   ```bash
   # tests/.env
   TEST_ADMIN_EMAIL=admin@wildbox.local
   TEST_ADMIN_PASSWORD=ChangeMe123!
   TEST_USER_EMAIL=test@wildbox.local
   TEST_USER_PASSWORD=TestPass123!
   IDENTITY_SERVICE_URL=http://localhost:8001
   ```

3. Update test files to use environment variables:
   ```python
   # tests/integration/test_identity_comprehensive.py
   import os
   from dotenv import load_dotenv

   load_dotenv("tests/.env")

   DEFAULT_ADMIN_EMAIL = os.getenv("TEST_ADMIN_EMAIL")
   DEFAULT_ADMIN_PASSWORD = os.getenv("TEST_ADMIN_PASSWORD")
   ```

4. Generate test API keys for service-to-service auth

5. Re-run Identity tests

**Acceptance Criteria:**
- [ ] Identity tests: 7/8 passing (from 1/8)
- [ ] Authentication flows validated
- [ ] API key management working

---

### Task 1.2: Investigate & Fix Responder Service Issues

**Priority**: CRITICAL ⚡
**Effort**: 3-4 hours
**Impact**: +5 tests (Responder service)

**Steps:**
1. Check Responder service logs for errors:
   ```bash
   docker-compose logs responder | tail -100
   ```

2. Verify Responder health endpoint manually:
   ```bash
   curl http://localhost:8018/health
   curl http://localhost:8018/api/v1/playbooks
   ```

3. Investigate test file for incorrect assumptions:
   ```bash
   # Read test file and check endpoints
   cat tests/integration/test_responder_metrics.py
   ```

4. Common issues to check:
   - Incorrect port (should be 8018)
   - Missing playbook files
   - Database connection issues
   - Redis connection issues

5. Fix identified issues

6. Re-run Responder tests

**Acceptance Criteria:**
- [ ] Responder tests: 3+/5 passing (from 0/5)
- [ ] Service health check passing
- [ ] Playbook list accessible

---

### Task 1.3: Fix LLM Service for Agents

**Priority**: HIGH 🟠
**Effort**: 2-3 hours
**Impact**: +4 tests (Agents service)

**Steps:**
1. Check LLM service status:
   ```bash
   docker-compose ps llm
   docker-compose logs llm | tail -50
   ```

2. Identify why LLM is unhealthy:
   - Model not downloaded?
   - GPU/CPU resource issues?
   - Configuration error?

3. Common fixes:
   ```bash
   # Restart LLM service
   docker-compose restart llm

   # Check resource usage
   docker stats llm

   # Verify model is loaded
   curl http://localhost:11434/health
   curl http://localhost:11434/v1/models
   ```

4. If using vLLM with Qwen2.5-0.5B, verify configuration:
   ```bash
   docker-compose exec llm env | grep MODEL
   ```

5. Alternative: Switch to OpenAI temporarily:
   ```bash
   # In .env
   OPENAI_API_KEY=sk-your-key-here
   OPENAI_BASE_URL=""  # Empty = use OpenAI
   ```

6. Re-run Agents tests

**Acceptance Criteria:**
- [ ] LLM service healthy
- [ ] Agents tests: 4+/5 passing (from 1/5)
- [ ] AI analysis working

---

### Task 1.4: Fix Gateway Rate Limiting Test

**Priority**: MEDIUM 🟡
**Effort**: 2-3 hours
**Impact**: +1 test

**Steps:**
1. Review test expectations:
   ```python
   # tests/integration/test_gateway_security.py
   # Check rate limiting test
   ```

2. Verify Gateway rate limiting configuration:
   ```bash
   # Check nginx config
   docker-compose exec gateway cat /etc/nginx/nginx.conf | grep limit
   ```

3. Update test to match actual implementation

4. Re-run Gateway tests

**Acceptance Criteria:**
- [ ] Gateway tests: 5+/7 passing (from 4/7)

---

### Task 1.5: Fix Simple Tool Execution Test

**Priority**: MEDIUM 🟡
**Effort**: 2-3 hours
**Impact**: +1 test

**Steps:**
1. Investigate why simple execution fails but complex succeeds:
   ```python
   # tests/integration/test_tools_execution.py
   # Compare test_simple_tool_execution vs test_multiple_tool_execution
   ```

2. Check if it's an endpoint path issue:
   ```bash
   # Test simple execution manually
   curl -X POST http://localhost:8000/api/v1/tools/whois_lookup/execute \
     -H "Content-Type: application/json" \
     -d '{"domain": "example.com"}'
   ```

3. Fix test or service endpoint

**Acceptance Criteria:**
- [ ] Tools tests: 4+/6 passing (from 3/6)

---

### Phase 1 Summary

**Expected Results:**
- Success Rate: 43% → **57% (+14%)**
- Tests Passing: 28 → **45 (+17 tests)**
- Perfect Services: 2 → **4-5**

**Deliverables:**
- [ ] `tests/.env` configuration file
- [ ] Authentication working for all services
- [ ] LLM service healthy
- [ ] Responder service tests passing
- [ ] Updated TEST_BASELINE_REPORT.md

---

## Phase 2: Foundation (Weeks 2-4)

**Goal**: Add critical missing test coverage
**Target Success Rate**: 62-65%
**Estimated Effort**: 30-40 hours

### Task 2.1: Add Individual Security Tool Tests

**Priority**: HIGH 🟠
**Effort**: 12-16 hours
**Impact**: +10-15 new tests

**Approach:**
1. Create new test file: `tests/integration/test_individual_tools.py`

2. Test top 10 most critical tools:
   - whois_lookup
   - dns_enumerator
   - port_scanner
   - ssl_analyzer
   - subdomain_scanner
   - jwt_analyzer
   - hash_generator
   - password_generator
   - ip_geolocation
   - url_analyzer

3. Template for each tool test:
   ```python
   async def test_whois_lookup_execution(self) -> bool:
       """Test whois_lookup tool with valid domain"""
       try:
           response = requests.post(
               f"{self.base_url}/api/v1/tools/whois_lookup/execute",
               json={"domain": "example.com"},
               timeout=30
           )

           passed = response.status_code == 200
           if passed:
               result = response.json()
               # Validate result structure
               passed = "registrar" in result or "whois" in result

           self.log_test_result("WHOIS Lookup Execution", passed, ...)
           return passed
       except Exception as e:
           ...
   ```

4. Validate:
   - Tool accepts correct parameters
   - Tool returns expected output structure
   - Tool handles errors gracefully
   - Tool timeout works

**Deliverables:**
- [ ] test_individual_tools.py with 10+ tool tests
- [ ] Documentation of tool parameter schemas
- [ ] Tool execution benchmark data

---

### Task 2.2: Add Integration Workflow Tests

**Priority**: HIGH 🟠
**Effort**: 10-12 hours
**Impact**: +8-10 new tests

**Scenarios to Test:**

1. **Vulnerability Detection → Response Workflow**
   ```
   Guardian detects vulnerability
   → Creates finding
   → Triggers Responder playbook
   → Executes remediation actions
   → Updates finding status
   ```

2. **IOC Analysis Workflow**
   ```
   User submits IP address
   → Agents AI analysis starts
   → Calls whois_lookup tool
   → Calls ip_reputation tool
   → Stores results in Data service
   → Generates report
   ```

3. **Dashboard → API → Backend Workflow**
   ```
   Dashboard requests threat intel data
   → Gateway routes to Data service
   → Data service queries Elasticsearch
   → Results aggregated
   → Returned to Dashboard
   ```

**Implementation:**
Create `tests/integration/test_workflows.py`

**Deliverables:**
- [ ] test_workflows.py with 3+ end-to-end scenarios
- [ ] Workflow documentation
- [ ] Performance benchmarks

---

### Task 2.3: Expand Data Service Tests

**Priority**: MEDIUM 🟡
**Effort**: 6-8 hours
**Impact**: +3-5 new tests

**Focus Areas:**
1. Fix failing tests:
   - `test_threat_intel_feeds`
   - `test_team_scoped_data_insertion`
   - `test_data_retrieval_scoping`

2. Add new tests:
   - GraphQL API testing
   - Bulk data operations
   - Data aggregation queries
   - Historical data retrieval

**Deliverables:**
- [ ] Data tests: 8+/12 passing
- [ ] GraphQL test coverage
- [ ] Bulk operation tests

---

### Task 2.4: Team & Multi-tenancy Tests

**Priority**: MEDIUM 🟡
**Effort**: 8-10 hours
**Impact**: +10-12 new tests

**Test Coverage:**
1. Team creation and management
2. User assignment to teams
3. Data isolation by team
4. Asset scoping by team
5. RBAC enforcement by team

**Implementation:**
Create `tests/integration/test_multitenancy.py`

**Deliverables:**
- [ ] test_multitenancy.py with 10+ tests
- [ ] Team isolation validated
- [ ] RBAC enforcement tested

---

### Phase 2 Summary

**Expected Results:**
- Success Rate: 57% → **64% (+7%)**
- Tests Passing: 45 → **75 (+30 tests)**
- New Test Files: +3 files
- Critical Workflows: Validated

---

## Phase 3: Expansion (Weeks 5-8)

**Goal**: Comprehensive coverage of all features
**Target Success Rate**: 68-70%
**Estimated Effort**: 40-50 hours

### Task 3.1: Compliance & Reporting Tests

**Priority**: MEDIUM 🟡
**Effort**: 10-12 hours
**Impact**: +8-10 tests

**Coverage:**
- Compliance framework checks
- Report generation (vulnerability, compliance, audit)
- Export functionality (PDF, CSV, JSON)
- Scheduled reports

---

### Task 3.2: Advanced Gateway Tests

**Priority**: MEDIUM 🟡
**Effort**: 8-10 hours
**Impact**: +6-8 tests

**Coverage:**
- SSL/TLS termination
- Request/response transformation
- API versioning
- Advanced rate limiting (per plan)
- Circuit breaker edge cases

---

### Task 3.3: Performance & Load Testing

**Priority**: MEDIUM 🟡
**Effort**: 12-16 hours
**Impact**: Platform stability validation

**Tests:**
- API endpoint load tests (100+ concurrent requests)
- Database query performance
- Celery task queue performance
- Memory leak detection
- Response time degradation under load

**Tools:**
- Locust for load testing
- pytest-benchmark for performance regression

---

### Task 3.4: Error Handling & Edge Cases

**Priority**: LOW 🟢
**Effort**: 8-10 hours
**Impact**: +10-15 tests

**Coverage:**
- Invalid input handling
- Error message validation
- Timeout scenarios
- Network failure simulation
- Database connection loss
- Service unavailability

---

### Phase 3 Summary

**Expected Results:**
- Success Rate: 64% → **69% (+5%)**
- Tests Passing: 75 → **95 (+20 tests)**
- Platform stability: Validated under load
- Error handling: Comprehensive coverage

---

## Phase 4: Excellence (Ongoing)

**Goal**: Maintain and optimize test suite
**Target Success Rate**: 70%+ sustained
**Effort**: 10-15 hours/month

### Ongoing Activities

1. **Test Maintenance**
   - Fix flaky tests
   - Update tests for API changes
   - Refactor duplicate code

2. **Performance Optimization**
   - Reduce test execution time
   - Parallel test execution
   - Test data fixtures

3. **Coverage Monitoring**
   - Weekly coverage reports
   - Trend analysis
   - Gap identification

4. **New Feature Testing**
   - Tests for each new feature
   - Regression test suite expansion

---

## Metrics & Monitoring

### Success Metrics

| Metric | Current | Week 1 | Week 4 | Week 8 | Target |
|--------|---------|--------|--------|--------|--------|
| Success Rate | 43% | 57% | 64% | 69% | 70% |
| Tests Passing | 28/65 | 45/80 | 75/115 | 95/135 | 100+/140+ |
| Services Perfect | 2/9 | 4/9 | 6/9 | 7/9 | 8/9 |
| Code Coverage | 0%* | 5% | 15% | 25% | 30% |
| Functional Coverage | 38% | 45% | 55% | 62% | 65% |

*Current 0% because integration tests don't import code directly

---

### Weekly Reporting

**Template:**
```markdown
## Week N Test Report

**Success Rate**: X% (±Y% from last week)
**Tests Added**: N new tests
**Tests Fixed**: N tests
**New Failures**: N tests
**Flaky Tests**: N tests

**Highlights**:
- [Achievement 1]
- [Achievement 2]

**Blockers**:
- [Blocker 1]

**Next Week Focus**:
- [Task 1]
- [Task 2]
```

---

## Resource Allocation

### Team Requirements

**Week 1** (Quick Wins):
- 1 senior engineer (full-time)
- 20 hours

**Weeks 2-4** (Foundation):
- 1 senior engineer (50%)
- 1 QA engineer (50%)
- 40 hours total

**Weeks 5-8** (Expansion):
- 1 QA engineer (full-time)
- 50 hours

**Ongoing** (Excellence):
- 1 QA engineer (25%)
- 10-15 hours/month

---

## Risk Management

### Risks & Mitigation

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Auth config breaks existing functionality | Medium | High | Test in isolated environment first |
| LLM service can't be fixed | Low | High | Use OpenAI as fallback |
| New tests introduce flakiness | High | Medium | Implement retry logic, use fixtures |
| Time estimates exceeded | Medium | Medium | Prioritize critical tests, defer nice-to-haves |
| Breaking changes in services | Low | High | Version lock dependencies, thorough testing |

---

## Dependencies & Prerequisites

### Before Starting Phase 1:
- [ ] Docker services all running
- [ ] pytest-cov installed
- [ ] Access to service logs
- [ ] .env files configured

### Before Starting Phase 2:
- [ ] Phase 1 complete (55%+ success rate)
- [ ] Authentication working
- [ ] All services healthy
- [ ] Test data fixtures created

### Before Starting Phase 3:
- [ ] Phase 2 complete (64%+ success rate)
- [ ] Load testing tools installed (Locust)
- [ ] Performance baseline established

---

## Appendix: Quick Reference

### Useful Commands

```bash
# Run full test suite
python run_integration_tests.py

# Run specific service tests
pytest tests/integration/test_guardian_monitoring.py -v

# Run with coverage
pytest tests/integration/ --cov=open-security-guardian --cov-report=html

# Check service health
for port in 8001 8002 8000 8006 8013 8018; do
  curl -sf http://localhost:$port/health && echo "Port $port: OK" || echo "Port $port: FAIL"
done

# View service logs
docker-compose logs -f [service-name]

# Restart services
docker-compose restart [service-name]
```

### Test File Locations

- Integration tests: `tests/integration/`
- Unit tests: `tests/` and `[service]/tests/`
- E2E tests: `open-security-dashboard/tests/e2e/`
- Test utilities: `tests/utils/`

---

**Next Actions**:
1. Review and approve this action plan
2. Allocate resources (1 senior engineer for Week 1)
3. Create Week 1 detailed task breakdown
4. Begin Phase 1: Quick Wins

**Plan Owner**: Test Infrastructure Team
**Last Updated**: 16 November 2025
**Review Cadence**: Weekly
**Contact**: fabrizio.salmi@gmail.com

---

## Approval

- [ ] Plan Reviewed
- [ ] Resources Allocated
- [ ] Timeline Approved
- [ ] Ready to Execute

**Approved By**: _______________
**Date**: _______________
