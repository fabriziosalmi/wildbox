# Wildbox Documentation Style Guide

**Version**: 1.0  
**Last Updated**: 2025-11-24  
**Purpose**: Enforce consistency and quality across all Wildbox documentation

## Table of Contents

- [General Principles](#general-principles)
- [Writing Style](#writing-style)
- [Markdown Formatting](#markdown-formatting)
- [Code Examples](#code-examples)
- [API Documentation](#api-documentation)
- [Accessibility](#accessibility)
- [Inclusive Language](#inclusive-language)

---

## General Principles

### 1. Accuracy Over Marketing
- ❌ "Enterprise-grade", "NASA-level", "Military-grade"
- ✅ Specific technical claims: "Handles 10,000 req/sec", "99.9% uptime SLA"

### 2. Honesty About Limitations
- Document what the software **cannot** do
- List known bugs and workarounds
- Be explicit about alpha/beta status

### 3. Respect Reader's Time
- Front-load key information
- Use tables and lists over paragraphs
- Add "Time to Read" for documents >1000 words

---

## Writing Style

### Voice and Tone

**Use Active Voice**:
- ❌ "An email is sent to the user"
- ✅ "The system sends an email to the user"

**Be Direct**:
- ❌ "Simply click the button"
- ❌ "Just run this command"
- ✅ "Click the button"
- ✅ "Run this command"

**Avoid Condescension**:
- ❌ "Obviously, you need to install Docker first"
- ✅ "Install Docker before proceeding"

**No Self-Deprecation**:
- ❌ "This is a hack, sorry"
- ✅ "This workaround exists because [technical constraint]"

### Grammar

**Present Tense**:
- ❌ "The API will return a response"
- ✅ "The API returns a response"

**Second Person**:
- ❌ "Users should configure their environment"
- ✅ "Configure your environment"

**Consistent Terminology**:
- Pick one term and use it consistently
- Bad: Switching between "User", "Client", "Customer"
- Good: Always use "User" in identity service docs

---

## Markdown Formatting

### Headers

**Title Case for H2 and Above**:
- ✅ `## Quick Start Guide`
- ❌ `## Quick start guide`

**Sentence case for H3 and Below**:
- ✅ `### Installing dependencies`
- ❌ `### Installing Dependencies`

**No Punctuation in Headers**:
- ✅ `## Configuration`
- ❌ `## Configuration:`

### Lists

**Use Dashes for Unordered Lists**:
```markdown
- Item one
- Item two
  - Nested item
```

**Numbers for Sequential Steps**:
```markdown
1. First step
2. Second step
3. Third step
```

**Consistent Bullet Formatting**:
- ❌ Mixing `-`, `*`, and `+`
- ✅ Always use `-`

### Code Blocks

**Always Specify Language**:
````markdown
❌ Bad:
```
docker-compose up
```

✅ Good:
```bash
docker-compose up
```
````

**Supported Languages**:
- `bash` (shell commands)
- `python`
- `typescript` / `javascript`
- `json`, `yaml`, `toml`
- `sql`
- `dockerfile`
- `nginx`
- `lua`

### Links

**Descriptive Link Text**:
- ❌ `For more info, [click here](https://docs.wildbox.io)`
- ✅ `See the [complete API documentation](https://docs.wildbox.io)`

**No Bare URLs**:
- ❌ `Visit https://wildbox.io for details`
- ✅ `Visit [Wildbox](https://wildbox.io) for details`

### Images

**Always Include Alt Text**:
```markdown
❌ ![](diagram.png)
✅ ![Architecture diagram showing 11 microservices connected via API gateway](diagram.png)
```

**Alt Text Guidelines**:
- Describe what the image shows
- Include relevant context for screen readers
- Don't just repeat the caption

---

## Code Examples

### Prerequisites

**Always Document Requirements**:
```markdown
## Prerequisites

Before running this example:

- Docker 20.10+
- Python 3.11+
- PostgreSQL 15 (via Docker Compose)
```

### Expected Output

**Show Success Looks Like**:
````markdown
```bash
curl http://localhost:8001/health

# Expected output:
{
  "status": "healthy",
  "service": "identity",
  "timestamp": "2025-11-24T12:00:00Z"
}
```
````

### Error Handling

**Document Common Errors**:
````markdown
```bash
docker-compose up -d

# If you see "port already allocated":
docker-compose down
lsof -ti:8001 | xargs kill -9
docker-compose up -d
```
````

### Environment Variables

**Explain Every Variable**:
```bash
# JWT_SECRET_KEY: Secret for signing authentication tokens
# - Minimum 256 bits (64 characters)
# - Rotate quarterly
# - Generate: openssl rand -base64 64
JWT_SECRET_KEY=your-secret-here

# POSTGRES_PASSWORD: Database password
# - Complexity: 16+ chars, alphanumeric + symbols
# - DO NOT use default in production
POSTGRES_PASSWORD=your-password-here
```

---

## API Documentation

### Endpoint Format

```markdown
### `GET /api/v1/users/{user_id}`

Retrieve user details by ID.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `user_id` | UUID | Yes | Unique user identifier |

**Headers**:
```http
Authorization: Bearer <jwt_token>
Content-Type: application/json
```

**Response** (200 OK):
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "is_active": true,
  "created_at": "2025-01-15T10:30:00Z"
}
```

**Errors**:
- `401 Unauthorized`: Missing or invalid JWT token
- `404 Not Found`: User does not exist
- `403 Forbidden`: Insufficient permissions
```

### Status Codes

**Always Document**:
- 2xx success codes
- 4xx client errors
- 5xx server errors

### Data Types

**Be Specific**:
- ❌ "Returns user data"
- ✅ "Returns `User` object with `id` (UUID), `email` (string), `is_active` (boolean)"

---

## Accessibility

### Screen Reader Compatibility

1. **Alt text on all images**
2. **Descriptive link text** (no "click here")
3. **Semantic HTML** in documentation sites
4. **Proper heading hierarchy** (H1 → H2 → H3, no skipping)

### Color Blindness

**Don't Rely on Color Alone**:
- ❌ "Click the red button"
- ✅ "Click the 'Delete' button (red)"

### International Audiences

**Date Format**: Always use ISO 8601
- ✅ `2025-11-24`
- ❌ `11/24/2025` (ambiguous US/EU)
- ❌ `24/11/2025`

**Time Zones**: Specify or use UTC
- ✅ `2025-11-24T14:30:00Z` (UTC)
- ✅ `2025-11-24T14:30:00-05:00` (EST)

**Units**: Spell out or use standard abbreviations
- ✅ `16GB RAM`
- ❌ `16G memory` (ambiguous)

---

## Inclusive Language

### Avoid

| ❌ Don't Use | ✅ Use Instead |
|--------------|----------------|
| Master/Slave | Main/Replica, Primary/Secondary |
| Whitelist/Blacklist | Allowlist/Denylist |
| Sanity check | Validity check, Integrity check |
| Guys | Team, Everyone, Folks |
| Crazy, Insane | Unexpected, Surprising |
| Dummy value | Placeholder, Sample value |

### Gender-Neutral Language

- ❌ "When the user opens his browser"
- ✅ "When the user opens their browser"
- ✅ "When you open your browser"

---

## Acronyms and Abbreviations

### Define on First Use

```markdown
Wildbox uses **Role-Based Access Control (RBAC)** to manage permissions. 
RBAC allows administrators to assign roles with specific capabilities.
```

### Glossary

For documents with many terms, add a glossary:

```markdown
## Glossary

- **CSPM**: Cloud Security Posture Management
- **IOC**: Indicator of Compromise
- **SOAR**: Security Orchestration, Automation, and Response
- **SIEM**: Security Information and Event Management
```

---

## Version Specificity

### Tag Documentation

```markdown
---
version: 0.2.0
last_updated: 2025-11-24
applies_to: Wildbox >= 0.2.0
---

# Feature X Documentation
```

### Deprecation Notices

```markdown
> **⚠️ DEPRECATED**: This feature is deprecated as of v0.3.0 and will be removed in v0.5.0.
> Use [new feature](link) instead. See [migration guide](link).
```

---

## File Naming Conventions

### Documentation Files

- Lowercase with hyphens: `api-reference.md`
- Descriptive names: `gateway-authentication-guide.md`
- Avoid abbreviations: `configuration.md` not `config.md`

### Avoid Generic Names

- ❌ `README.md` in every folder
- ✅ `SERVICE_NAME_README.md` or embed in main docs

---

## Metadata

### Every Document Should Have

```markdown
---
title: Service Lifecycle Documentation
description: Operational procedures for managing Wildbox microservices
version: 1.0
last_updated: 2025-11-24
maintainer: DevOps Team
related_docs:
  - OBSERVABILITY_ROADMAP.md
  - GATEWAY_AUTHENTICATION_GUIDE.md
---
```

---

## Quality Checklist

Before committing documentation, verify:

- [ ] Spell check passed (`cspell`)
- [ ] Markdown lint passed (`markdownlint`)
- [ ] Links validated (`markdown-link-check`)
- [ ] All code blocks have language specified
- [ ] All images have alt text
- [ ] All acronyms defined on first use
- [ ] No hardcoded secrets in examples
- [ ] Expected output shown for CLI commands
- [ ] Prerequisites clearly stated
- [ ] Date format is ISO 8601
- [ ] No "simply", "just", "obviously"
- [ ] Active voice used
- [ ] Inclusive language checked

---

## Tools

Run these before every commit:

```bash
# Spell check
cspell "**/*.md" --config .cspell.json

# Markdown linting
markdownlint "**/*.md" --config .markdownlint.json

# Link validation
markdown-link-check README.md --config .markdown-link-check.json

# Prose quality (advisory)
proselint README.md

# Inclusive language
alex "**/*.md"
```

---

## Related Documentation

- [CONTRIBUTING.md](../CONTRIBUTING.md) - Contribution guidelines
- [DOCUMENTATION_QUALITY_AUDIT.md](DOCUMENTATION_QUALITY_AUDIT.md) - Current quality status
- [ARCHITECTURE_DECISIONS.md](ARCHITECTURE_DECISIONS.md) - Technical decision records

---

**Last Updated**: 2025-11-24  
**Review Cycle**: Quarterly  
**Owner**: Documentation Team
