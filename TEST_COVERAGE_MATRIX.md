# Wildbox Test Coverage Matrix

**Quick Reference**: Test coverage status per service

## Coverage Overview

| Service | Files | Integration | Unit | E2E | Script | Status | Priority |
|---------|-------|-------------|------|-----|--------|--------|----------|
| **Dashboard** | 7 | ✅ 1 | - | ✅ 6 | - | 🟢 Excellent | Low |
| **Responder** | 5 | ✅ 1 | ✅ 1 | ✅ 1 | ✅ 1 | 🟢 Good | Low |
| **Identity** | 4 | ✅ 1 | ✅ 2 | - | - | 🟢 Good | Low |
| **Agents** | 3 | ✅ 1 | ✅ 1 | - | ✅ 1 | �� Adequate | Medium |
| **Data** | 2 | ✅ 1 | ✅ 1 | - | - | 🟡 Adequate | Medium |
| **Tools** | 2 | ✅ 1 | - | - | - | 🔴 Minimal | **HIGH** |
| **Gateway** | 1 | ✅ 1 | - | - | - | 🔴 Critical | **URGENT** |
| **Guardian** | 1 | ✅ 1 | - | - | - | 🔴 Minimal | **HIGH** |
| **CSPM** | 1 | ✅ 1 | - | - | - | 🔴 Minimal | Medium |
| **Sensor** | 1 | ✅ 1 | - | - | - | 🔴 Minimal | Medium |
| **Automations** | 1 | ✅ 1 | - | - | - | 🔴 Minimal | Medium |

## Legend

- ✅ = Has test coverage
- 🟢 = Well covered (5+ files)
- 🟡 = Adequately covered (2-4 files)
- 🔴 = Minimal coverage (1 file)

## Critical Gaps

### 🚨 URGENT: Gateway Service
**Current**: 1 integration test only  
**Risk**: Gateway is entry point for ALL traffic  
**Missing**:
- Rate limiting tests
- Lua authentication logic tests
- Request routing tests
- GATEWAY_INTERNAL_SECRET validation
- CORS/security headers tests

**Recommended Actions**:
1. Add `test_gateway_rate_limiting.py`
2. Add `test_gateway_auth_flow.py`
3. Add `test_gateway_routing.py`
4. Add `test_gateway_security_headers.py`

### ⚠️ HIGH: Tools Service
**Current**: 1 integration test + 1 standalone  
**Risk**: 55+ security tools need individual validation  
**Missing**:
- Per-tool execution tests
- Tool chaining/workflow tests
- Error handling tests
- Timeout/resource limit tests

**Recommended Actions**:
1. Create `tests/tools/` directory
2. Add test per tool category (recon, vuln scan, etc.)
3. Add `test_tool_orchestration.py`

### ⚠️ HIGH: Guardian Service
**Current**: 1 integration test only  
**Risk**: Vulnerability management is core functionality  
**Missing**:
- Vulnerability detection logic tests
- Risk scoring algorithm tests
- Alert generation tests
- Remediation workflow tests

**Recommended Actions**:
1. Add `test_guardian_detection.py`
2. Add `test_guardian_risk_scoring.py`
3. Add `test_guardian_alerts.py`

## Test Type Distribution

```
Current:
├── Integration: 11 files (46%) ✅ Good
├── Unit:         7 files (29%) ⚠️ Should be 50%
├── E2E:          7 files (29%) ✅ Excellent for frontend
├── Script:       2 files (8%)  ℹ️ Optional
└── Standalone:   3 files (13%) ℹ️ Should migrate to pytest

Target:
├── Integration: 40%
├── Unit:        50%
└── E2E:         10%
```

## Framework Standardization

**Current State**:
- Custom Classes: 58% (14 files)
- Pytest: 9% (2 files)
- Unknown: 33% (8 files)

**Recommendation**: Migrate to Pytest

**Benefits**:
- Industry standard
- Better fixture management
- Parallel execution
- Rich plugin ecosystem
- Better CI/CD integration

## Quick Actions Checklist

### Week 1: Critical Coverage
- [ ] Add Gateway rate limiting tests
- [ ] Add Gateway auth flow tests
- [ ] Add Gateway routing tests
- [ ] Add Tools per-category tests

### Week 2: Framework Migration
- [ ] Create pytest migration plan
- [ ] Migrate 5 custom class tests to pytest
- [ ] Set up pytest.ini configuration
- [ ] Add pytest-asyncio plugin

### Week 3: Guardian & CSPM
- [ ] Add Guardian detection tests
- [ ] Add Guardian risk scoring tests
- [ ] Add CSPM checks validation
- [ ] Add CSPM remediation tests

### Week 4: Documentation & CI
- [ ] Create tests/README.md
- [ ] Document test execution
- [ ] Add GitHub Actions workflow
- [ ] Set up pre-commit hooks

## Coverage Goals

| Timeframe | Target | Details |
|-----------|--------|---------|
| **1 Month** | 60% | Fill critical gaps (Gateway, Tools, Guardian) |
| **3 Months** | 75% | Migrate to pytest, add unit tests |
| **6 Months** | 85% | Performance tests, security tests |

---

**Last Updated**: 16 November 2025  
**Source Data**: `test_inventory.json`  
**Full Report**: `TEST_SUITE_AUDIT_REPORT.md`
