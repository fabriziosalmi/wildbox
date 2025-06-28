# 🎯 Wildbox Master Pulse Check System

## Overview

The Wildbox Master Pulse Check is a comprehensive testing system that validates the entire Wildbox security ecosystem to ensure it's 100% "Production Ready". The system tests 60+ individual components across 11 services.

## Architecture

```
pulse_check.py                    # Main orchestrator
├── tests/
│   ├── integration/             # Service-specific test modules
│   │   ├── test_identity_comprehensive.py    # 🔐 Identity Service
│   │   ├── test_gateway_security.py          # 🛡️ API Gateway
│   │   ├── test_tools_execution.py           # 🔧 Security Tools
│   │   ├── test_data_integration.py          # 📊 Threat Intel Data
│   │   ├── test_guardian_monitoring.py       # 🛡️ Asset Management
│   │   ├── test_sensor_telemetry.py          # 📡 Endpoint Monitoring
│   │   ├── test_responder_metrics.py         # 🎯 Incident Response
│   │   ├── test_agents_ai.py                 # 🤖 AI Analysis
│   │   ├── test_cspm_compliance.py           # ☁️ Cloud Security
│   │   ├── test_automations_workflow.py      # ⚙️ n8n Workflows
│   │   └── test_dashboard_frontend.py        # 🖥️ Web Interface
│   ├── utils/                   # Shared utilities
│   │   ├── auth_helpers.py      # Authentication management
│   │   ├── test_data_generator.py # Test data creation
│   │   └── report_generator.py  # HTML/JSON reporting
│   └── reports/                 # Generated reports
│       ├── pulse_check_report.html
│       └── detailed_results.json
```

## Tested Components

### Core Services
- **🔐 Identity Service (Port 8001)**: Authentication, JWT, RBAC, billing integration
- **🛡️ Gateway (Port 80/443)**: Routing, security headers, rate limiting, circuit breaker

### Satellite Services  
- **🔧 Tools (Port 8000)**: 57+ security tools, execution pipeline, plan-based protection
- **📊 Data (Port 8002)**: IOC lookup, 50+ threat intel feeds, team-scoped data
- **🛡️ Guardian (Port 8013)**: Asset management, vulnerabilities, Celery tasks
- **📡 Sensor (Port 8004)**: osquery monitoring, telemetry, remote configuration
- **🎯 Responder (Port 8018)**: Playbooks, metrics endpoint, execution monitoring
- **🤖 Agents (Port 8006)**: OpenAI integration, AI analysis, report generation
- **☁️ CSPM (Port 8019)**: Cloud compliance, scanning, findings management
- **⚙️ Automations (Port 5678)**: n8n workflows, webhook execution

### Frontend
- **🖥️ Dashboard (Port 3000)**: UI loading, navigation, data visualization

## Test Categories

Each service includes comprehensive tests for:

- ✅ **Service Health**: Endpoint responsivity and basic functionality
- ✅ **Authentication**: JWT tokens, API keys, RBAC validation
- ✅ **Core Features**: Primary service capabilities
- ✅ **Security**: Headers, rate limiting, input validation
- ✅ **Integration**: Inter-service communication
- ✅ **Performance**: Response times and throughput
- ✅ **Error Handling**: Graceful failure and recovery

## Usage

### Prerequisites
- All Wildbox services running via Docker Compose
- Network connectivity to all service ports
- Valid OPENAI_API_KEY environment variable (for AI tests)

### Quick Test
```bash
# Dry run to verify system integrity
python3 test_pulse_check_system.py

# Full production readiness check
python3 pulse_check.py
```

### Expected Output
```
🚀 Wildbox Master Pulse Check - Production Ready Verification
================================================================================
🔧 Setting up test environment...
🧪 Starting 🔐 Identity Service: Authentication, JWT, RBAC, Billing
✅ Identity Service: Authentication, JWT, RBAC, Billing - PASSED (8 tests)
🧪 Starting 🛡️ Gateway: Routing, Security Headers, Rate Limiting  
✅ Gateway: Routing, Security Headers, Rate Limiting - PASSED (7 tests)
...
🎉 🎉 WILDBOX IS 100% PRODUCTION READY! 🎉 🎉
✅ All 65 tests passed across 11 modules
🚀 Ready for production deployment!
```

## Reports

### HTML Dashboard
Interactive dashboard with:
- Overall success status
- Module-by-module results
- Test execution metrics
- Visual progress indicators
- Detailed error information

### JSON Results
Machine-readable results for CI/CD integration:
```json
{
  "overall_success": true,
  "total_tests": 65,
  "passed_tests": 65,
  "total_modules": 11,
  "successful_modules": 11,
  "timestamp": "2024-01-01T12:00:00Z"
}
```

## CI/CD Integration

The pulse check system is designed for continuous integration:

```yaml
# GitHub Actions example
- name: Wildbox Production Readiness Check
  run: |
    python3 pulse_check.py
    if [ $? -eq 0 ]; then
      echo "✅ Wildbox is Production Ready"
    else
      echo "❌ Wildbox needs attention"
      exit 1
    fi
```

## Customization

### Adding New Tests
1. Create test module in `tests/integration/`
2. Implement `run_tests()` async function
3. Add module to orchestrator's test list
4. Return structured results with test details

### Test Module Template
```python
async def run_tests() -> Dict[str, Any]:
    tester = YourServiceTester()
    
    tests = [
        tester.test_health,
        tester.test_feature_x,
        tester.test_feature_y
    ]
    
    success_count = 0
    for test in tests:
        success = await test()
        if success:
            success_count += 1
    
    return {
        "success": success_count == len(tests),
        "tests": tester.test_results,
        "summary": f"{success_count}/{len(tests)} tests passed"
    }
```

## Success Criteria

The system achieves "Production Ready" status when:

- ✅ **All 60+ tests pass** with green status
- ✅ **overall_success: true** in final report
- ✅ **Zero critical errors** in service logs  
- ✅ **Response times** under defined thresholds
- ✅ **Dashboard** fully functional without UI errors

## Troubleshooting

### Common Issues

**Services Not Ready**
```bash
# Check service status
docker-compose ps
docker-compose logs [service-name]
```

**Authentication Failures**
```bash
# Verify JWT_SECRET_KEY and API keys
grep JWT_SECRET_KEY docker-compose.yml
```

**Network Connectivity**
```bash
# Test service endpoints
curl http://localhost:8001/health
curl http://localhost:8000/health
```

### Debug Mode
```bash
# Run with detailed logging
DEBUG=true python3 pulse_check.py
```

---

**🎯 When all tests pass, Wildbox is certified 100% Production Ready! 🚀**