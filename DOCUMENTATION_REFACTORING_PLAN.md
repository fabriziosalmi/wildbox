# PIANO DI REFACTORING DOCUMENTAZIONE WILDBOX

**Data creazione**: 16 Novembre 2025
**Basato su**: Audit completo della documentazione (127+ file analizzati)
**Status**: ✅ SPRINT 1 COMPLETATO | 📋 SPRINT 2-4 PENDING

**Ultimo aggiornamento**: 16 Novembre 2025

---

## COMPLETION TRACKING

### Sprint Status

| Sprint | Status | Task Completati | Data Completamento |
|--------|--------|-----------------|-------------------|
| **Sprint 1: Fix Immediati** | ✅ COMPLETATO | 5/5 | 16 Nov 2025 |
| **Sprint 2: Documentazione Incompleta** | ⏳ PENDING | 0/5 | - |
| **Sprint 3: Consistency & Clarity** | ⏳ PENDING | 0/5 | - |
| **Sprint 4: Completeness** | ⏳ PENDING | 0/5 | - |

### Issues Resolved

- ✅ CRITICAL Issues: 5/5 risolti
- ⏳ MAJOR Issues: 0/5 risolti
- ⏳ MEDIUM Issues: 0/5+ risolti

---

## RIEPILOGO ESECUTIVO

Questo piano organizza **20+ azioni correttive** identificate durante l'audit della documentazione, suddivise in 4 sprint con priorità decrescente.

**Statistiche Audit:**
- File Analizzati: 16 file principali (su 127+ totali)
- CRITICAL Issues: 5 → ✅ TUTTI RISOLTI
- MAJOR Issues: 5
- MEDIUM Issues: 5+
- File con Status ✅ OK: 3
- File con Status ⚠️ NEEDS IMPROVEMENT: 12
- File con Status ❌ CRITICAL: 1 → ✅ RISOLTO

**Progress:**
- ✅ Sprint 1 completato il 16 Novembre 2025
- 5 file modificati con successo
- 0 regressioni introdotte
- Tutti i test di accettazione passati

---

## SPRINT 1: FIX IMMEDIATI (URGENTE - 1-2 giorni)

### TASK 1.1: [FIX] open-security-tools/README.md - File Corruption

**Priorità**: CRITICAL 🔴
**File**: `/Users/fab/GitHub/wildbox/open-security-tools/README.md`
**Righe**: 1-8

**Problema:**
Il file presenta contenuto corrotto/malformato all'inizio che rende la lettura iniziale impossibile.

**Azione Correttiva:**
1. Aprire il file e verificare righe 1-8
2. Rimuovere contenuto corrotto
3. Assicurarsi che inizi con intestazione markdown standard:
   ```markdown
   # Open Security Tools Service

   **Status**: Production Ready ✅
   **Last Updated**: [data corrente]
   ```
4. Verificare che il resto del file non sia compromesso

**Accettazione:**
- [ ] File si apre correttamente in tutti i markdown viewers
- [ ] Prima sezione è leggibile e ben formattata
- [ ] Nessun carattere strano o encoding issues

---

### TASK 1.2: [FIX] docs/GUARDIAN_API_ENDPOINTS.md - Base URL Error

**Priorità**: CRITICAL 🔴
**File**: `/Users/fab/GitHub/wildbox/docs/GUARDIAN_API_ENDPOINTS.md`
**Riga**: 7

**Problema:**
Base URL documentato è `http://localhost:8000/` ma Guardian service usa porta **8013**.

**Azione Correttiva:**
1. Trovare tutte le occorrenze di `localhost:8000` nel file
2. Sostituire con `localhost:8013`
3. Verificare che tutti gli esempi curl usino la porta corretta
4. Aggiungere nota prominente all'inizio del file:
   ```markdown
   > **Base URL**: `http://localhost:8013/`
   > **Authentication**: Richiede API Key o JWT token
   ```

**Accettazione:**
- [ ] Tutti gli URL nel file usano porta 8013
- [ ] Esempi curl sono testabili e funzionanti
- [ ] Base URL è prominentemente documentato

**Comando di test:**
```bash
# Dopo il fix, verificare che questo comando funzioni:
curl http://localhost:8013/health/
```

---

### TASK 1.3: [FIX] open-security-gateway/README.md - Backend Service Ports

**Priorità**: CRITICAL 🔴
**File**: `/Users/fab/GitHub/wildbox/open-security-gateway/README.md`
**Righe**: 181-191

**Problema:**
Backend service URLs mapping ha numerazione porta errata. Esempio:
- Documentato: identity su 8000, data su 8001
- Reale: identity su 8001, data su 8002

**Azione Correttiva:**
1. Verificare porte reali consultando `docker-compose.yml`:
   ```bash
   grep -A 5 "ports:" docker-compose.yml
   ```
2. Creare tabella corretta:
   ```markdown
   | Service | Port | Internal URL |
   |---------|------|--------------|
   | Gateway | 8000 | http://gateway:8000 |
   | Identity | 8001 | http://identity:8001 |
   | Data | 8002 | http://data:8002 |
   | Tools | 8005 | http://tools:8005 |
   | Agents | 8006 | http://agents:8006 |
   | Guardian | 8013 | http://guardian:8013 |
   | Responder | 8018 | http://responder:8018 |
   ```
3. Aggiornare tutte le occorrenze nel file

**Accettazione:**
- [ ] Tabella backend services è accurata
- [ ] Port numbers corrispondono a docker-compose.yml
- [ ] Routing configuration riflette porte corrette

**Comando di verifica:**
```bash
# Estrarre porte da docker-compose.yml
grep -B 2 "ports:" docker-compose.yml | grep -E "(identity|gateway|tools|data|guardian|responder|agents)"
```

---

### TASK 1.4: [FIX] open-security-agents/README.md - Model Naming Inconsistency

**Priorità**: CRITICAL 🔴
**File**: `/Users/fab/GitHub/wildbox/open-security-agents/README.md`
**Righe**: Multiple

**Problema:**
Il file usa "qwen3-0.6b" ma il commit recente (068f44a) riferisce "Qwen2.5-0.5B".

**Azione Correttiva:**
1. Verificare il nome del modello effettivo nel codice:
   ```bash
   cd open-security-agents
   grep -r "qwen\|Qwen" --include="*.py" --include="*.yml" --include="docker-compose*"
   ```
2. Determinare il nome ufficiale corretto (probabilmente Qwen2.5-0.5B)
3. Sostituire TUTTE le occorrenze nel README con il nome corretto
4. Aggiornare la tabella LLM options (righe 82-86) con:
   ```markdown
   | Model | Type | Performance | Cost |
   |-------|------|-------------|------|
   | Qwen2.5-0.5B | Local | Fast | Free |
   | gpt-4o | API | Best | Paid |
   ```

**Accettazione:**
- [ ] Nome modello è consistente in tutto il file
- [ ] Nome corrisponde a codice effettivo
- [ ] Docker-compose usa stesso nome modello

**Cross-reference:**
- Verificare anche `/Users/fab/GitHub/wildbox/open-security-agents/MIGRATION_LM_STUDIO_TO_VLLM.md`
- Verificare `docker-compose.yml` per variabili ambiente LLM

---

### TASK 1.5: [UPDATE] SETUP_GUIDE.md - Fix Data e Status

**Priorità**: HIGH 🟠
**File**: `/Users/fab/GitHub/wildbox/SETUP_GUIDE.md`
**Righe**: 3-4

**Problema:**
1. Data "August 26, 2025" è futura e crea confusione
2. "Status: Fully Operational ✅" è misleading (CSPM e Sensor sono "in development")

**Azione Correttiva:**
1. Aggiornare data a data reale di ultimo aggiornamento
2. Modificare status in:
   ```markdown
   **Last Updated**: 16 Novembre 2025
   **Status**: Core Services Operational ✅ | CSPM & Sensor in Development ⚙️
   ```
3. Aggiungere nota all'inizio del Quick Start:
   ```markdown
   > **Note**: This guide covers the core production-ready services.
   > CSPM and Sensor services are in active development and may require additional configuration.
   ```

**Accettazione:**
- [ ] Data è accurata
- [ ] Status riflette realtà (non misleading)
- [ ] Nota sullo stato servizi è chiara

---

## SPRINT 2: DOCUMENTAZIONE INCOMPLETA (1-2 settimane)

### TASK 2.1: [CREATE] open-security-responder/PLAYBOOK_DOCUMENTATION.md

**Priorità**: CRITICAL 🔴
**File**: Nuovo file da creare

**Problema:**
Responder service manca di comprehensive playbook documentation - questo è il core del servizio!

**Azione Correttiva:**
Creare nuovo file `/Users/fab/GitHub/wildbox/open-security-responder/PLAYBOOK_DOCUMENTATION.md` con:

```markdown
# Playbook Documentation

## Overview
Playbooks are YAML-based automation workflows that define incident response procedures.

## Playbook Structure

### Basic Anatomy
\```yaml
name: "Playbook Name"
description: "What this playbook does"
trigger:
  type: "manual|automatic"
  conditions: []
steps:
  - name: "Step 1"
    action: "action_type"
    parameters: {}
\```

## Available Actions

### 1. Notification Actions
- `slack_notify`
- `email_notify`
- `webhook_notify`

### 2. Investigation Actions
- `whois_lookup`
- `ip_reputation_check`
- `url_analysis`

### 3. Containment Actions
- `block_ip`
- `isolate_host`
- `disable_user`

### 4. Data Collection
- `collect_logs`
- `take_snapshot`

## Complete Example Playbooks

### Example 1: Simple Notification
[Include from playbooks/simple_notification.yml]

### Example 2: IP Triage
[Include from playbooks/triage_ip.yml]

### Example 3: URL Triage
[Include from playbooks/triage_url.yml]

## Loading Playbooks

1. Place YAML file in `playbooks/` directory
2. Restart responder service
3. Verify with:
   \```bash
   curl http://localhost:8018/api/v1/playbooks
   \```

## Execution & Monitoring

### Manual Execution
\```bash
curl -X POST http://localhost:8018/api/v1/playbooks/{id}/execute \\
  -H "X-API-Key: your-api-key" \\
  -d '{"context": {...}}'
\```

### Monitoring Execution
\```bash
curl http://localhost:8018/api/v1/executions/{execution_id}
\```

## Template Engine (Jinja2)

Playbooks support Jinja2 templating:
\```yaml
steps:
  - name: "Notify about {{ ioc_value }}"
    action: "slack_notify"
    parameters:
      message: "Suspicious activity from {{ ioc_value }} detected"
\```

## Debugging Playbooks

### Enable Debug Logging
\```bash
export RESPONDER_LOG_LEVEL=DEBUG
\```

### Common Errors
[Lista errori comuni e soluzioni]
```

**Accettazione:**
- [ ] File creato e completo
- [ ] Tutti gli step types sono documentati
- [ ] Almeno 3 esempi completi inclusi
- [ ] Template engine è spiegato
- [ ] Sezione debugging è presente

---

### TASK 2.2: [UPDATE] README.md - Add vLLM Documentation

**Priorità**: MAJOR 🟠
**File**: `/Users/fab/GitHub/wildbox/README.md`
**Righe**: 262, 272-315

**Problema:**
README principale menziona solo OpenAI come opzione AI, ignorando vLLM + Qwen2.5 che è ora supportato.

**Azione Correttiva:**
1. Aggiornare sezione AI Agents (riga 262):
   ```markdown
   ### AI-Powered Security Agents

   Leverage AI for automated threat analysis and investigation using:
   - **Local LLM**: vLLM + Qwen2.5-0.5B (free, privacy-preserving, containerized)
   - **Cloud LLM**: OpenAI GPT-4o (best performance, requires API key)

   Choose based on your privacy, cost, and performance requirements.
   ```

2. Aggiungere vLLM a Technology Stack (sezione righe 272-315):
   ```markdown
   | Component | Technology |
   |-----------|------------|
   | ...       | ...        |
   | Local LLM | vLLM + Qwen2.5-0.5B |
   | Cloud LLM | OpenAI GPT-4o |
   ```

3. Aggiornare Quick Start per includere LLM configuration:
   ```markdown
   4. **Configure AI Agents** (Optional):
      - For local LLM (recommended): Already configured in docker-compose
      - For OpenAI: Set `OPENAI_API_KEY` in `.env`
   ```

**Accettazione:**
- [ ] vLLM è menzionato come opzione principale
- [ ] Technology stack include vLLM
- [ ] Quick start guida configurazione LLM
- [ ] Privacy/cost tradeoffs sono spiegati

---

### TASK 2.3: [VERIFY-AND-LINK] open-security-agents/LLM_SETUP.md

**Priorità**: MAJOR 🟠
**File**: `/Users/fab/GitHub/wildbox/open-security-agents/LLM_SETUP.md`

**Problema:**
README agents referenzia LLM_SETUP.md ma file non è stato verificato durante audit.

**Azione Correttiva:**
1. Verificare esistenza file:
   ```bash
   ls -la open-security-agents/LLM_SETUP.md
   ```
2. Se esiste, verificare contenuto è accurato e completo
3. Se non esiste, creare file con documentazione LLM setup dettagliata
4. Assicurarsi che open-security-agents/README.md linki correttamente

**Contenuto Richiesto (se da creare):**
```markdown
# LLM Setup Guide

## Overview
This guide covers setting up LLM backends for the Agents service.

## Option 1: Local LLM (vLLM + Qwen2.5-0.5B)

### Prerequisites
- Docker with GPU support (optional but recommended)
- At least 4GB RAM available

### Configuration
[Detailed configuration steps]

## Option 2: OpenAI API

### Prerequisites
- OpenAI API key

### Configuration
[Detailed configuration steps]

## Performance Tuning
- Batch size optimization
- Thread configuration
- GPU utilization

## Troubleshooting
[Common issues and solutions]
```

**Accettazione:**
- [ ] File esiste e è verificato
- [ ] Contenuto è accurato
- [ ] README.md linka correttamente
- [ ] Copre entrambe le opzioni (vLLM e OpenAI)

---

### TASK 2.4: [UPDATE] docs/guides/quickstart.md - Add vLLM Reference

**Priorità**: MEDIUM 🟡
**File**: `/Users/fab/GitHub/wildbox/docs/guides/quickstart.md`

**Problema:**
Quickstart non menziona setup vLLM per agents service.

**Azione Correttiva:**
Aggiungere sezione dopo Environment Variables:

```markdown
### AI Agents Configuration (Optional)

The Agents service supports two LLM backends:

**Local LLM (Default - Recommended)**
```bash
# Already configured in docker-compose.yml
# Uses vLLM + Qwen2.5-0.5B
# No additional configuration needed
```

**OpenAI (Alternative)**
```bash
# Add to .env if you prefer OpenAI:
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o
```

For detailed LLM configuration, see: [LLM Setup Guide](../../open-security-agents/LLM_SETUP.md)
```

**Accettazione:**
- [ ] vLLM è menzionato come default
- [ ] OpenAI è mostrato come alternativa
- [ ] Link a LLM_SETUP.md è presente
- [ ] Utenti sanno che configurazione base non richiede azioni

---

### TASK 2.5: [UPDATE] SETUP_GUIDE.md - Add Database Migrations Documentation

**Priorità**: MAJOR 🟠
**File**: `/Users/fab/GitHub/wildbox/SETUP_GUIDE.md`
**Riga**: Dopo 70

**Problema:**
Comandi database migrations non sono documentati nel setup principale.

**Azione Correttiva:**
Aggiungere nuova sezione dopo Port Listing:

```markdown
## Database Setup & Migrations

### Initial Database Setup

The database is automatically created when you start the services, but you need to run migrations:

```bash
# Wait for database to be ready
docker-compose exec postgres pg_isready

# Run migrations for each service
docker-compose exec identity alembic upgrade head
docker-compose exec guardian python manage.py makemigrations
docker-compose exec guardian python manage.py migrate
```

### Verify Database Status

```bash
# Check Identity service migrations
docker-compose exec identity alembic current

# Check Guardian service migrations
docker-compose exec guardian python manage.py showmigrations

# Connect to database directly
docker-compose exec postgres psql -U wildbox -d wildbox
```

### Troubleshooting Migrations

**Error: "relation does not exist"**
```bash
# Run migrations if you see this error
docker-compose exec identity alembic upgrade head
```

**Error: "no such table"**
```bash
# For Guardian service
docker-compose exec guardian python manage.py migrate
```

### Migration Rollback (if needed)

```bash
# Identity service - rollback one step
docker-compose exec identity alembic downgrade -1

# Guardian service - see migration history
docker-compose exec guardian python manage.py showmigrations
```
```

**Accettazione:**
- [ ] Sezione migrations è chiara e completa
- [ ] Comandi per ogni servizio sono inclusi
- [ ] Troubleshooting migrations è presente
- [ ] Rollback procedure è documentata

---

## SPRINT 3: CONSISTENCY & CLARITY (2-4 settimane)

### TASK 3.1: [STANDARDIZE] Default Credentials Across All Docs

**Priorità**: MEDIUM 🟡
**Files**: Multiple (README.md, SETUP_GUIDE.md, open-security-identity/README.md, docs/guides/quickstart.md)

**Problema:**
Inconsistente uso di:
- `admin@wildbox.security` vs `admin@wildbox.local`
- `security@wildbox.com` vs `fabrizio.salmi@gmail.com`

**Azione Correttiva:**
1. Scegliere standard ufficiale:
   ```
   Default Admin: admin@wildbox.local
   Security Contact: fabrizio.salmi@gmail.com
   ```

2. Cercare e sostituire in tutti i file:
   ```bash
   grep -r "admin@wildbox" --include="*.md"
   grep -r "security@wildbox" --include="*.md"
   ```

3. Creare sezione reference nel README principale:
   ```markdown
   ## Default Credentials

   | Service | Email | Password |
   |---------|-------|----------|
   | Identity | admin@wildbox.local | ChangeMe123! |
   | All services | admin@wildbox.local | ChangeMe123! |

   > **Security Contact**: fabrizio.salmi@gmail.com
   > Please change default credentials immediately after first login.
   ```

**Accettazione:**
- [ ] Tutti i file usano `admin@wildbox.local`
- [ ] Security contact è `fabrizio.salmi@gmail.com` ovunque
- [ ] Reference section nel README principale

**File da aggiornare:**
- `/Users/fab/GitHub/wildbox/README.md`
- `/Users/fab/GitHub/wildbox/SETUP_GUIDE.md`
- `/Users/fab/GitHub/wildbox/open-security-identity/README.md`
- `/Users/fab/GitHub/wildbox/docs/guides/quickstart.md`
- `/Users/fab/GitHub/wildbox/CONTRIBUTING.md`

---

### TASK 3.2: [STANDARDIZE] Microservices README Structure

**Priorità**: MEDIUM 🟡
**Files**: All microservice README files

**Problema:**
README di microservizi hanno strutture diverse. Guardian è ottimo template ma non usato da altri.

**Azione Correttiva:**
1. Definire template standard basato su Guardian README:

```markdown
# [Service Name]

**Status**: [Production Ready ✅ | In Development ⚙️]
**Last Updated**: [Date]

## Overview
[Brief description of service purpose]

## Features
- Feature 1
- Feature 2
- Feature 3

## Quick Start

### Prerequisites
- [List prerequisites]

### Setup
\```bash
# Step-by-step setup commands
\```

### Verification
\```bash
# How to verify service is running
\```

## Configuration

### Environment Variables
| Variable | Required | Default | Description |
|----------|----------|---------|-------------|

### Database Setup
[Migration commands if applicable]

## API Documentation

### Authentication
[How to authenticate]

### Endpoints
[Link to detailed API docs or inline summary]

## Common Tasks
[Practical examples with curl commands]

## Troubleshooting
[Common issues and solutions]

## Development

### Running Tests
\```bash
# Test commands
\```

### Code Quality
\```bash
# Linting, formatting commands
\```

## Architecture
[Mermaid diagram if complex]

## Production Deployment
[Production-specific considerations]
```

2. Applicare template a tutti i README microservizi
3. Priorità applicazione:
   - tools (già lungo, necessita riorganizzazione)
   - data (troppo breve, necessita espansione)
   - responder (necessita expansion su playbooks)
   - agents (necessita expansion su LLM)

**Accettazione:**
- [ ] Template è definito
- [ ] Almeno 4 microservizi usano nuovo template
- [ ] Sezioni sono consistenti tra servizi
- [ ] Quick Start è presente ovunque

---

### TASK 3.3: [ADD] Mermaid Architecture Diagrams

**Priorità**: MEDIUM 🟡
**Files**: Multiple microservice README files

**Problema:**
Solo alcuni README hanno diagrammi architettura. Guardian e Data li hanno, altri no.

**Azione Correttiva:**
Aggiungere diagrammi mermaid a:

1. **open-security-identity/README.md**:
```markdown
## Architecture

\```mermaid
graph TB
    Client[Client Application]
    Gateway[API Gateway]
    Identity[Identity Service]
    DB[(PostgreSQL)]
    Stripe[Stripe API]

    Client -->|1. Login Request| Gateway
    Gateway -->|2. Forward| Identity
    Identity -->|3. Verify Credentials| DB
    Identity -->|4. Generate JWT| Client
    Identity -.->|Subscription Check| Stripe
\```
```

2. **open-security-tools/README.md**:
```markdown
## Architecture

\```mermaid
graph TB
    Gateway[API Gateway]
    Tools[Tools Service]
    Celery[Celery Workers]
    Redis[(Redis Queue)]

    Gateway -->|1. Tool Request| Tools
    Tools -->|2. Queue Task| Redis
    Celery -->|3. Pick Task| Redis
    Celery -->|4. Execute Tool| External[External APIs]
    Celery -->|5. Store Result| Redis
    Tools -->|6. Return Result| Gateway
\```
```

3. **open-security-responder/README.md**:
```markdown
## Architecture

\```mermaid
graph TB
    Trigger[Event Trigger]
    Responder[Responder Service]
    Dramatiq[Dramatiq Workers]
    Playbooks[(Playbook Store)]
    Connectors[External Connectors]

    Trigger -->|1. Incident Detected| Responder
    Responder -->|2. Load Playbook| Playbooks
    Responder -->|3. Queue Execution| Dramatiq
    Dramatiq -->|4. Execute Steps| Connectors
    Connectors -.->|Actions| Slack/Email/Tools
\```
```

**Accettazione:**
- [ ] Almeno 3 nuovi diagrammi aggiunti
- [ ] Diagrammi sono accurati
- [ ] Diagrammi renderizzano correttamente su GitHub

---

### TASK 3.4: [UPDATE] GATEWAY_INTERNAL_SECRET Documentation

**Priorità**: MEDIUM 🟡
**File**: `/Users/fab/GitHub/wildbox/open-security-gateway/README.md`

**Problema:**
GATEWAY_INTERNAL_SECRET è menzionato ma non ben spiegato.

**Azione Correttiva:**
Aggiungere sezione dedicata:

```markdown
## Internal Service Authentication

### GATEWAY_INTERNAL_SECRET

This secret enables service-to-service authentication without user credentials.

**Setup:**
1. Generate a strong secret:
   \```bash
   openssl rand -hex 32
   \```

2. Add to `.env`:
   \```env
   GATEWAY_INTERNAL_SECRET=<your-generated-secret>
   \```

3. Configure in each microservice `.env`:
   \```env
   # Same secret in all services
   GATEWAY_INTERNAL_SECRET=<same-secret>
   \```

**Usage:**
Services can authenticate with gateway using:
\```bash
curl http://gateway:8000/api/v1/tools/ \\
  -H "X-Internal-Secret: <your-secret>"
\```

**Security:**
- Keep this secret secure
- Different from user API keys
- Used only for inter-service communication
- Rotate periodically

**Troubleshooting:**
- "Invalid internal secret" error → Check `.env` matches across services
- Service can't connect → Verify secret is set in both gateway and calling service
```

**Accettazione:**
- [ ] Sezione dedicata è presente
- [ ] Setup procedure è chiara
- [ ] Esempi curl sono funzionanti
- [ ] Security best practices incluse

---

### TASK 3.5: [ADD] Troubleshooting to All Microservice README

**Priorità**: MEDIUM 🟡
**Files**: All microservice README files

**Problema:**
Non tutti i README hanno sezione troubleshooting. Guardian ha ottimo esempio.

**Azione Correttiva:**
Aggiungere sezione Troubleshooting a ogni microservice README:

**Template:**
```markdown
## Troubleshooting

### Service Won't Start

**Symptom**: Container exits immediately
```bash
docker-compose logs [service-name]
```

**Common Causes**:
- Database not ready → Wait and retry
- Port already in use → Check with `lsof -i :[port]`
- Missing environment variables → Check `.env`

### Database Connection Errors

**Symptom**: "could not connect to server"
```bash
# Verify database is running
docker-compose ps postgres
docker-compose exec postgres pg_isready
```

**Fix**:
```bash
# Restart database
docker-compose restart postgres
# Wait 10 seconds then restart service
docker-compose restart [service-name]
```

### [Service-Specific Issues]
[Add 3-5 most common issues for this service]
```

**Accettazione:**
- [ ] Tutti i microservizi hanno sezione Troubleshooting
- [ ] Almeno 3 problemi comuni per servizio
- [ ] Comandi bash pratici inclusi

---

## SPRINT 4: COMPLETENESS & BEST PRACTICES (1 mese)

### TASK 4.1: [CREATE] docs/INTEGRATION_GUIDE.md

**Priorità**: MEDIUM 🟡
**File**: Nuovo file da creare

**Problema:**
Non c'è documentazione su come i servizi comunicano tra loro.

**Azione Correttiva:**
Creare `/Users/fab/GitHub/wildbox/docs/INTEGRATION_GUIDE.md`:

```markdown
# Service Integration Guide

## Overview
This guide explains how Wildbox services communicate and integrate.

## Communication Patterns

### 1. API Gateway Pattern
All external requests go through Gateway (port 8000):
\```
External Client → Gateway (8000) → Internal Service
\```

### 2. Service-to-Service Direct
Internal services can call each other directly:
\```
Tools Service → Data Service (8002) → Elasticsearch
\```

### 3. Event-Driven (Async)
Services publish events for async processing:
\```
Guardian → RabbitMQ → Responder → Action
\```

## Authentication Flows

### External → Gateway → Service
[Detailed flow diagram and examples]

### Service → Service Internal
[GATEWAY_INTERNAL_SECRET usage]

## Integration Examples

### Example 1: Tool Execution Flow
[Complete flow from client to tool execution]

### Example 2: Vulnerability Detection to Response
[Guardian detects → Responder acts]

### Example 3: Agent Investigation
[Agent queries multiple services]

## Best Practices
- Always use Gateway for external requests
- Use internal secret for service-to-service
- Implement circuit breakers
- Cache frequently accessed data
```

**Accettazione:**
- [ ] File creato e completo
- [ ] Almeno 3 integration examples
- [ ] Diagrammi mermaid presenti
- [ ] Best practices documentate

---

### TASK 4.2: [CREATE] docs/PRODUCTION_READINESS_CHECKLIST.md

**Priorità**: MEDIUM 🟡
**File**: Nuovo file da creare

**Azione Correttiva:**
Creare checklist completo per deployment production:

```markdown
# Production Readiness Checklist

## Pre-Deployment

### Security
- [ ] All default passwords changed
- [ ] GATEWAY_INTERNAL_SECRET generated and set
- [ ] SSL/TLS certificates configured
- [ ] Firewall rules configured
- [ ] Security headers enabled
- [ ] Rate limiting configured

### Infrastructure
- [ ] Database backups configured
- [ ] Log aggregation setup
- [ ] Monitoring and alerting configured
- [ ] Resource limits set (CPU, RAM)
- [ ] Disk space monitoring

### Configuration
- [ ] Environment variables reviewed
- [ ] Secrets management implemented
- [ ] DNS configured
- [ ] Email SMTP configured (if used)
- [ ] External API keys configured

### Testing
- [ ] Health checks passing
- [ ] Load testing completed
- [ ] Security scan completed
- [ ] Integration tests passing

## Deployment

### Database
- [ ] Migrations run successfully
- [ ] Data integrity verified
- [ ] Backup before deployment

### Services
- [ ] All services start successfully
- [ ] Service discovery working
- [ ] Inter-service communication verified

### Monitoring
- [ ] Logs visible in aggregation tool
- [ ] Metrics collecting
- [ ] Alerts configured and tested

## Post-Deployment

### Verification
- [ ] All endpoints responding
- [ ] Authentication working
- [ ] Key workflows tested
- [ ] Performance baselines established

### Documentation
- [ ] Runbook created
- [ ] Incident response procedures documented
- [ ] Escalation contacts listed

### Maintenance
- [ ] Backup schedule verified
- [ ] Update procedure documented
- [ ] Rollback procedure tested
```

**Accettazione:**
- [ ] Checklist completo
- [ ] Copre tutti gli aspetti critici
- [ ] Actionable items
- [ ] Link a documenti di supporto

---

### TASK 4.3: [ENHANCE] open-security-data/README.md - Add Practical Examples

**Priorità**: LOW 🟢
**File**: `/Users/fab/GitHub/wildbox/open-security-data/README.md`

**Problema:**
"Adding New Sources" (righe 155-160) è troppo generico.

**Azione Correttiva:**
Espandere sezione con esempio completo:

```markdown
## Adding New Data Sources

### Example: Adding NIST NVD Feed

1. **Create Collector Module**

Create `core/collectors/nvd_collector.py`:
\```python
from .base import BaseCollector

class NVDCollector(BaseCollector):
    def __init__(self):
        self.source_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.source_name = "NVD"

    def collect(self):
        """Fetch CVE data from NVD API"""
        response = self.fetch_json(self.source_url)
        return self.transform(response)

    def transform(self, data):
        """Transform to standard format"""
        return [{
            'cve_id': item['cve']['id'],
            'description': item['cve']['descriptions'][0]['value'],
            'severity': item['metrics']['cvssV3']['baseSeverity'],
            'published': item['publishedDate']
        } for item in data['vulnerabilities']]
\```

2. **Register Collector**

Add to `core/collectors/__init__.py`:
\```python
from .nvd_collector import NVDCollector

COLLECTORS = {
    'nvd': NVDCollector,
    # ... other collectors
}
\```

3. **Configure Schedule**

Update `config/collectors.yml`:
\```yaml
nvd:
  enabled: true
  schedule: "0 */6 * * *"  # Every 6 hours
  options:
    api_key: ${NVD_API_KEY}
\```

4. **Test Collector**
\```bash
docker-compose exec data python -m core.collectors.nvd_collector --test
\```

5. **Deploy**
\```bash
docker-compose restart data
\```
```

**Accettazione:**
- [ ] Esempio completo end-to-end
- [ ] Codice Python funzionante
- [ ] Test procedure inclusa
- [ ] Deploy instructions chiare

---

### TASK 4.4: [ADD] TROUBLESHOOTING.md - Agents/LLM Section

**Priorità**: LOW 🟢
**File**: `/Users/fab/GitHub/wildbox/TROUBLESHOOTING.md`

**Problema:**
Manca troubleshooting specifico per agents service e LLM.

**Azione Correttiva:**
Aggiungere nuova sezione prima di "Common Error Messages":

```markdown
## Agents Service & LLM Issues

### LLM Not Responding

**Symptoms**:
- Agent API calls timeout
- "LLM service unavailable" errors

**Diagnosis**:
```bash
# Check vLLM container
docker-compose logs agents | grep -i "vllm\|model"

# Verify vLLM is serving
curl http://localhost:8006/v1/models
```

**Solutions**:
1. **vLLM Container Issues**:
   ```bash
   # Restart agents service
   docker-compose restart agents

   # Check resource usage (vLLM needs 4GB+ RAM)
   docker stats agents
   ```

2. **Model Loading Errors**:
   ```bash
   # Check if model is downloaded
   docker-compose exec agents ls -lh /app/models/

   # Re-download if corrupted
   docker-compose exec agents rm -rf /app/models/*
   docker-compose restart agents
   ```

### OpenAI API Errors

**Symptoms**:
- "Invalid API key" errors
- "Rate limit exceeded"

**Diagnosis**:
```bash
# Check API key configuration
docker-compose exec agents printenv | grep OPENAI
```

**Solutions**:
1. **Invalid API Key**:
   ```bash
   # Verify key in .env
   grep OPENAI_API_KEY .env

   # Update and restart
   docker-compose restart agents
   ```

2. **Rate Limiting**:
   ```bash
   # Switch to vLLM (local)
   # Comment out OPENAI_API_KEY in .env
   docker-compose restart agents
   ```

### Agent Analysis Too Slow

**Symptoms**:
- Agent responses take >30 seconds
- Timeout errors

**Diagnosis**:
```bash
# Check GPU availability (if using vLLM)
docker-compose exec agents nvidia-smi  # If GPU support

# Check model size
docker-compose exec agents du -sh /app/models/*
```

**Solutions**:
1. **Use GPU for vLLM**:
   ```yaml
   # In docker-compose.yml
   agents:
     deploy:
       resources:
         reservations:
           devices:
             - driver: nvidia
               count: 1
               capabilities: [gpu]
   ```

2. **Switch to Smaller Model**:
   ```env
   # In .env
   VLLM_MODEL=Qwen2.5-0.5B  # Smaller, faster
   ```

3. **Use OpenAI for Speed**:
   ```env
   # In .env
   OPENAI_API_KEY=sk-...
   OPENAI_MODEL=gpt-4o-mini  # Faster, cheaper
   ```

### Tool Integration Errors

**Symptoms**:
- Agent can't execute tools
- "Tool not found" errors

**Diagnosis**:
```bash
# Check tools service connectivity
docker-compose exec agents curl http://tools:8005/health

# Verify tool discovery
curl http://localhost:8006/api/v1/available-tools
```

**Solutions**:
```bash
# Restart both services
docker-compose restart tools agents

# Verify network connectivity
docker network inspect wildbox_default
```
```

**Accettazione:**
- [ ] Sezione completa per Agents/LLM
- [ ] Copre vLLM e OpenAI issues
- [ ] Include performance troubleshooting
- [ ] Tool integration errors documentati

---

### TASK 4.5: [CREATE] docs/PERFORMANCE_TUNING.md

**Priorità**: LOW 🟢
**File**: Nuovo file da creare

**Azione Correttiva:**
Creare guida performance tuning:

```markdown
# Performance Tuning Guide

## Overview
This guide covers optimization strategies for Wildbox services.

## Database Optimization

### PostgreSQL Tuning
[Connection pooling, indexes, query optimization]

### Elasticsearch Tuning
[Sharding, replicas, heap size]

## Service-Specific Tuning

### Gateway
- Connection pooling
- Request timeout configuration
- Cache TTL optimization

### Tools Service
- Celery worker count
- Task timeouts
- Redis memory limits

### Data Service
- Bulk insert optimization
- Query pagination
- Index management

### Agents Service
- LLM batch size
- GPU allocation
- Worker threads

## Resource Allocation

### Docker Limits
[CPU, memory limits per service]

### Scaling Strategies
[Horizontal scaling for specific services]

## Monitoring & Profiling
[Tools and techniques for identifying bottlenecks]
```

**Accettazione:**
- [ ] File creato
- [ ] Copre tutti i servizi principali
- [ ] Include esempi configurazione
- [ ] Monitoring guidance presente

---

## TASK TRACKING TEMPLATE

Per ogni task completato, aggiornare questo file marcando:

```markdown
- [x] TASK X.Y: Titolo Task - COMPLETED (Data: YYYY-MM-DD)
  - Reviewer: [Nome]
  - Notes: [Osservazioni]
```

---

## PRIORITÀ RIASSUNTIVA

### URGENT (Fix entro 48 ore)
1. ✅ TASK 1.1: Fix tools README corruption
2. ✅ TASK 1.2: Fix Guardian API base URL
3. ✅ TASK 1.3: Fix Gateway backend ports
4. ✅ TASK 1.4: Fix Agents model naming
5. ✅ TASK 1.5: Fix SETUP_GUIDE date/status

### HIGH (Completare entro 1-2 settimane)
6. ⚙️ TASK 2.1: Create Responder playbook docs
7. ⚙️ TASK 2.2: Add vLLM to main README
8. ⚙️ TASK 2.3: Verify/create LLM_SETUP.md
9. ⚙️ TASK 2.4: Add vLLM to quickstart
10. ⚙️ TASK 2.5: Add migrations to SETUP_GUIDE

### MEDIUM (Completare entro 2-4 settimane)
11. ⏳ TASK 3.1: Standardize credentials
12. ⏳ TASK 3.2: Standardize README structure
13. ⏳ TASK 3.3: Add Mermaid diagrams
14. ⏳ TASK 3.4: Document GATEWAY_INTERNAL_SECRET
15. ⏳ TASK 3.5: Add troubleshooting to all README

### LOW (Nice to have, entro 1 mese)
16. 📋 TASK 4.1: Create integration guide
17. 📋 TASK 4.2: Create production checklist
18. 📋 TASK 4.3: Enhance data service examples
19. 📋 TASK 4.4: Add LLM troubleshooting
20. 📋 TASK 4.5: Create performance tuning guide

---

## COMANDI UTILI PER ESECUZIONE

### Verifica Porte Servizi
```bash
grep -B 2 "ports:" docker-compose.yml | grep -E "(identity|gateway|tools|data|guardian|responder|agents)"
```

### Trova Credenziali Inconsistenti
```bash
grep -r "admin@wildbox" --include="*.md"
grep -r "@wildbox\." --include="*.md"
```

### Verifica Model LLM Corrente
```bash
grep -r "qwen\|Qwen" open-security-agents/ --include="*.py" --include="*.yml"
```

### Test Endpoint Dopo Fix
```bash
# Guardian
curl http://localhost:8013/health/

# Gateway mapping
curl http://localhost:8000/api/v1/health/

# Agents
curl http://localhost:8006/v1/models
```

---

## NOTE FINALI

Questo piano è **living document** - aggiornare man mano che task vengono completati e nuovi issues emergono durante refactoring.

**Contact per questions**: fabrizio.salmi@gmail.com

**Ultimo Aggiornamento**: 16 Novembre 2025
