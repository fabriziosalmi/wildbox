# Open Security Data

## Quick Start Guide

Congratulations! You now have a comprehensive security data lake platform. Here's how to get started:

### 1. Setup Environment

```bash
# Copy environment configuration
cp .env.example .env

# Edit configuration as needed
nano .env

# Install dependencies
pip install -r requirements.txt
```

### 2. Initialize Database

```bash
# Initialize database tables
python manage.py init

# Add default threat intelligence sources
python manage.py sources add-defaults

# List configured sources
python manage.py sources list
```

### 3. Start the Platform

#### Option A: Docker (Recommended)
```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f
```

#### Option B: Manual
```bash
# Start API server
python -m app.api.main &

# Start data collection scheduler
python -m app.scheduler.main &
```

### 4. Access the Platform

- **API Documentation**: http://localhost:8001/docs
- **Health Check**: http://localhost:8001/health
- **Statistics**: http://localhost:8001/api/v1/stats

### 5. Basic Usage Examples

#### Search for indicators
```bash
# Search for malicious IPs
curl "http://localhost:8001/api/v1/indicators/search?indicator_type=ip_address&threat_types=malware"

# Search for phishing domains
curl "http://localhost:8001/api/v1/indicators/search?indicator_type=domain&threat_types=phishing"
```

#### Lookup specific indicators
```bash
# Check IP address
curl "http://localhost:8001/api/v1/ips/1.2.3.4"

# Check domain
curl "http://localhost:8001/api/v1/domains/malicious.example.com"

# Check file hash
curl "http://localhost:8001/api/v1/hashes/d41d8cd98f00b204e9800998ecf8427e"
```

#### Bulk lookup
```bash
curl -X POST "http://localhost:8001/api/v1/indicators/lookup" \
  -H "Content-Type: application/json" \
  -d '{
    "indicators": [
      {"indicator_type": "ip_address", "value": "1.2.3.4"},
      {"indicator_type": "domain", "value": "example.com"}
    ]
  }'
```

#### Real-time threat feed
```bash
# Get recent threats (NDJSON format)
curl "http://localhost:8001/api/v1/feeds/realtime?since_minutes=60"
```

### 6. Configuration

#### Adding API Keys for Premium Sources

Edit your `.env` file or source configurations:

```bash
# AbuseIPDB
python manage.py sources enable "AbuseIPDB Denylist"

# URLVoid (configure domains to check)
# Edit source config via database or API
```

#### Configuring Data Sources

```bash
# Enable/disable sources
python manage.py sources enable "PhishTank"
python manage.py sources disable "Malware Domain List"

# Test a source
python manage.py sources test "PhishTank"
```

### 7. Monitoring

Access Grafana dashboard: http://localhost:3000 (admin/admin123)

### 8. Data Architecture

The platform collects data from:

- **Public Threat Feeds**: Malware Domain List, PhishTank, Feodo Tracker
- **API Services**: AbuseIPDB, URLVoid, VirusTotal (with API keys)
- **RSS Feeds**: Security blogs and threat intelligence feeds
- **File-based Sources**: CSV, JSON, text files

Data is automatically:
- **Validated** for correctness
- **Normalized** for consistency  
- **Enriched** with geolocation, ASN, and other metadata
- **Deduplicated** to avoid redundancy
- **Indexed** for fast searching

### 9. Integration Examples

#### Python Client
```python
import requests

# Search for indicators
response = requests.get("http://localhost:8001/api/v1/indicators/search", 
                       params={"q": "malware", "limit": 100})
indicators = response.json()

# Check if IP is malicious
response = requests.get("http://localhost:8001/api/v1/ips/1.2.3.4")
if response.status_code == 200:
    print("IP found in threat intelligence!")
```

#### SIEM Integration
Use the real-time feed endpoint to stream threats into your SIEM:
```bash
curl -N "http://localhost:8001/api/v1/feeds/realtime" | jq .
```

### 10. Development

#### Adding New Data Sources

1. Create collector in `app/collectors/sources.py`
2. Register in `app/collectors/__init__.py`
3. Add configuration to database
4. Test collection

#### Extending the API

1. Add new endpoints in `app/api/main.py`
2. Define schemas in `app/schemas/api.py`
3. Update documentation

### Next Steps

- Configure premium API sources with your API keys
- Set up monitoring and alerting
- Integrate with your security tools
- Customize collection intervals
- Add custom threat intelligence sources

For detailed documentation, see the `/docs` directory.

For support, check the GitHub issues or discussions.
