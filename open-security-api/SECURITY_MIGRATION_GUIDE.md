# Security Integration Migration Guide

This guide explains how to gradually enable the new security controls without breaking your existing setup.

## 🚀 Quick Start (No Breaking Changes)

The security integration is **backward compatible**. Your existing setup will continue to work exactly as before.

### Current Status
- ✅ **Security controls are DISABLED by default**
- ✅ **All existing functionality preserved**
- ✅ **No breaking changes**
- ✅ **Optional gradual migration**

## 📋 Migration Steps

### Phase 1: Setup (Safe - No Changes to Behavior)

1. **Run the security setup script**:
   ```bash
   ./setup_security.sh
   ```
   This creates security configurations but keeps security DISABLED.

2. **Test your existing workflows**:
   ```bash
   ./test_security_integration.sh
   ```

3. **Start the application as usual**:
   ```bash
   python -m uvicorn app.main:app --reload
   ```

### Phase 2: Gradual Enablement (When Ready)

1. **Enable security controls** in `.env`:
   ```bash
   SECURITY_CONTROLS_ENABLED=true
   SECURITY_STRICT_MODE=false  # Start with graceful mode
   ```

2. **Configure authorized targets** in `/etc/security/authorized_targets.json`:
   ```json
   {
       "targets": [
           "https://your-test-domain.com",
           "192.168.1.0/24",
           ".your-domain.com"
       ]
   }
   ```

3. **Set up user permissions** in `/etc/security/user_permissions.json`:
   ```json
   {
       "your_user_id": [
           "read_only",
           "passive_scan",
           "active_scan"
       ]
   }
   ```

### Phase 3: Full Security (Production Ready)

1. **Enable strict mode** in `.env`:
   ```bash
   SECURITY_STRICT_MODE=true
   ```

2. **Configure API keys securely**:
   ```bash
   VIRUSTOTAL_API_KEY=your_real_api_key
   SHODAN_API_KEY=your_real_api_key
   ```

3. **Set up proper authentication** in your application.

## 🔄 Rollback Plan

If you encounter issues, you can instantly rollback:

1. **Disable security controls**:
   ```bash
   echo "SECURITY_CONTROLS_ENABLED=false" >> .env
   ```

2. **Restart the application**:
   ```bash
   # Application will work exactly as before
   python -m uvicorn app.main:app --reload
   ```

## 🛠️ Tool-Specific Changes

### SQL Injection Scanner
- **CHANGED**: Removed destructive payloads (`DROP TABLE`, `EXEC xp_cmdshell`)
- **SAFE**: Only uses non-destructive detection payloads
- **BENEFIT**: No risk of actually damaging target systems

### IoT Security Scanner  
- **CHANGED**: No longer includes hardcoded credentials in code
- **SAFE**: Loads credentials from secure configuration files
- **BENEFIT**: Credentials not exposed in version control

### JWT Analyzer
- **CHANGED**: No longer includes hardcoded secrets in code
- **SAFE**: Loads secrets from secure configuration files
- **BENEFIT**: Secrets not exposed in logs or code

## 🔐 Security Features (When Enabled)

### Input Validation
- URL validation and sanitization
- SQL injection pattern detection
- XSS and command injection protection
- File upload safety checks

### Authorization Controls
- User-based permissions (read-only, passive scan, active scan, etc.)
- Target authorization (whitelist-based)
- Rate limiting per user and operation type
- Audit logging for all security events

### Credential Management
- Encrypted credential storage
- Environment-based API key management
- Secure configuration file handling
- No hardcoded secrets in code

## 📊 Testing Strategy

### 1. Compatibility Testing
```bash
# Test without security (current behavior)
SECURITY_CONTROLS_ENABLED=false python -m uvicorn app.main:app --reload

# Test with security enabled
SECURITY_CONTROLS_ENABLED=true python -m uvicorn app.main:app --reload
```

### 2. Functional Testing
```bash
# Test SQL injection scanner (safe payloads only)
curl -X POST http://localhost:8000/api/tools/sql_injection_scanner \
     -H 'Content-Type: application/json' \
     -d '{"target_url": "https://httpbin.org/get?id=1"}'
```

### 3. Security Testing
```bash
# Test authorization (should fail without proper setup)
curl -X POST http://localhost:8000/api/tools/sql_injection_scanner \
     -H 'Content-Type: application/json' \
     -H 'X-User-ID: unauthorized_user' \
     -d '{"target_url": "https://malicious-site.com"}'
```

## 🚨 Important Notes

### Destructive Payloads Removed
The following **dangerous payloads have been REMOVED**:
- `'; DROP TABLE users--`
- `'; EXEC xp_cmdshell('dir')--`
- All `WAITFOR DELAY` and `SLEEP` commands
- System command execution attempts

### Hardcoded Credentials Removed
The following **hardcoded credentials have been REMOVED**:
- IoT default passwords in source code
- JWT secret lists in source code
- API keys in configuration files

### Network Scanning Changes
- Fake/simulated results replaced with real implementation notes
- Rate limiting added to prevent abuse
- Authorization required for active scanning

## 📞 Support

If you encounter issues during migration:

1. **Check logs**: Look for security-related errors in application logs
2. **Disable security**: Set `SECURITY_CONTROLS_ENABLED=false` to rollback
3. **Run tests**: Use `./test_security_integration.sh` to diagnose issues
4. **Review configuration**: Check files in `/etc/security/` or `~/.config/wildbox-security/`

## 🎯 Summary

- **Phase 1**: Setup security components (no behavior change)
- **Phase 2**: Enable security gradually with graceful mode
- **Phase 3**: Enable strict security for production
- **Rollback**: Instantly disable security if needed

The integration is designed to be **zero-impact** on existing workflows while providing a **clear path** to enhanced security when ready.
