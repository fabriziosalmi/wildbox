# Wildbox Open Security Automations

n8n workflows that call the Wildbox API on a schedule. n8n runs as the
optional `automations` service of the stack (image `n8nio/n8n:1.74.0`); it has
no UI or API of its own beyond n8n's.

## Workflows

| Workflow | File | Trigger | What it does |
| -------- | ---- | ------- | ------------ |
| Executive Security Dashboard Automation | `workflows/reporting/executive_security_dashboard.json` | Mondays 08:00 (n8n's timezone, UTC by default) | Reads the CSPM figures of the last 30 days and sends them by e-mail and to Slack |

That is the whole inventory. Nine other workflows were removed by pull
request #603 (issue #592): every one called endpoints that do not exist (or
services directly, which they do not accept), so none of them could run.
UPGRADING.md, section 11, lists them with the reason for each.

### Executive Security Dashboard Automation

The workflow makes three calls through the gateway, each with
`X-API-Key: $WILDBOX_API_KEY`:

| Call | Used for |
| ---- | -------- |
| `GET /api/v1/cspm/dashboard/summary?days=30` | accounts assessed, retained scans, compliance score, failed checks by severity |
| `GET /api/v1/cspm/compliance/summary?days=30` | resources with a failed check, compliance by framework |
| `GET /api/v1/cspm/compliance/findings?status=failed&days=30&limit=1000` | the failing checks, grouped by check: most severe first, then by resources affected (top five), with each check's remediation text |

All the figures come from the newest completed CSPM scan of each account in
the period. When no
scan completed in the period, the report says that there is nothing to report
instead of showing zeros or a score. When there are more than 1000 failed
checks, the report says the grouping covers the first 1000.

The report contains no figure that the API does not return: there is no
"posture score", trend or threat level, and no fixed list of risks or
recommendations. If an API call fails, the execution fails and n8n records
the error; nothing is sent.

## Setup

1. Start the stack, including the gateway, so that it writes its TLS
   certificate to `open-security-gateway/ssl/`. Then start n8n:

   ```bash
   docker compose --profile automations up -d automations
   ```

2. Create n8n's owner account, now. Open <http://127.0.0.1:5678> on the
   host (from another machine, through an SSH tunnel:
   `ssh -L 5678:127.0.0.1:5678 <host>`); a new instance shows its setup page,
   `/setup`, and the account created there owns the instance. Do this before
   anything else: until an owner exists, n8n lets whoever reaches port 5678
   create it, with no credential, and the owner runs code in a container
   that reaches the gateway. The port is published on the loopback interface
   only, but the containers on n8n's network reach it too. To check:

   ```bash
   curl -s http://127.0.0.1:5678/rest/settings | jq '.data.userManagement.showSetupOnFirstLoad'
   ```

   `false` means the owner exists; `true` means the instance is still to be
   claimed. n8n 1.74 has no command or setting that creates the owner ahead
   of the first start, and no basic auth: the `N8N_BASIC_AUTH_*` variables
   earlier releases set were ignored, and are gone.

   n8n encrypts the credentials saved in it with a key it generates on this
   first start and keeps in its data directory: the `config` file of
   `open-security-automations/n8n-data/` (`/home/node/.n8n/config` in the
   container). Keep that file with every backup of n8n's database: without
   it the saved credentials cannot be decrypted. Compose passes n8n no
   `N8N_ENCRYPTION_KEY`, and the one `make generate-secrets` used to write
   to `.env` was never used. Do not set the variable on an instance that
   already has a key: n8n 1.74 exits with `Mismatching encryption keys`
   when it differs from the file.

3. Create a personal API key in the dashboard (Settings > API keys) with the
   `read` scope, and set the variables in the root `.env`:

   | Variable | Value |
   | -------- | ----- |
   | `AUTOMATIONS_WILDBOX_API_KEY` | the API key (passed to n8n as `WILDBOX_API_KEY`) |
   | `WILDBOX_API_GATEWAY_URL` | optional; default `https://open-security-gateway` |
   | `SLACK_WEBHOOK_URL` | a Slack incoming webhook |
   | `EXECUTIVE_REPORT_EMAIL_FROM`, `EXECUTIVE_REPORT_EMAIL_TO` | sender and recipient of the report |

   Recreate the container after changing them
   (`docker compose --profile automations up -d automations`).

4. Import the workflows:

   ```bash
   ./open-security-automations/scripts/import_workflows.sh
   ```

   The script stages every JSON file under `workflows/` in the container and
   runs `n8n import:workflow`. Each workflow has a fixed id, so importing
   again updates it rather than adding a copy.

5. In n8n (<http://127.0.0.1:5678>), attach an SMTP credential to the
   "Send Executive Email" node, then activate the workflow. Imported
   workflows start inactive.

### Reaching n8n

n8n is reached on `127.0.0.1:5678` of the host and nowhere else. The gateway
does not route to it: `/api/v1/automations/`, which used to proxy to n8n's
editor, REST API and webhooks, answers 404. n8n is a single-tenant tool with
accounts of its own, and the gateway let every registered user of every team
through to it.

The workflows here need nothing inbound: they start on a schedule and call
the API outbound. A workflow that starts from a webhook is not reachable
from outside the host as shipped. Do not publish port 5678 for it; n8n's
webhooks are unauthenticated unless the webhook node is given credentials.

### Reaching the gateway

The gateway serves the API on its HTTPS listener only; port 80 and 8080
answer every API path with a redirect. The certificate the gateway generates
for development names `open-security-gateway`, and docker-compose.yml mounts
it (the certificate, not the key) into n8n and points `NODE_EXTRA_CA_CERTS`
at it, so n8n verifies the connection. With your own certificate, set
`WILDBOX_API_GATEWAY_URL` to a name the certificate covers and that resolves
from the n8n container.

## Writing a workflow

- Call Wildbox only through the gateway, with the URL starting
  `{{ $env.WILDBOX_API_GATEWAY_URL }}/api/v1/`. The services accept calls only
  from the gateway.
- Authenticate with an `X-API-Key` header (or `Authorization: Bearer`). The
  gateway does not accept a cookie.
- Give the workflow a fixed `"id"`, so that importing it twice does not
  create a copy.
- Show only what the API returns. When it has no data, say so; do not fill
  in a default value.
- Run the check that CI runs on every pull request:

  ```bash
  python3 scripts/check_automation_workflows.py
  ```

  It resolves the URL of every HTTP Request node, matches the path against
  the gateway configuration (`open-security-gateway/nginx/conf.d/wildbox_gateway.conf`)
  and the target service's routes, checks the method and the authentication
  header, and fails on a call that would not reach an existing route.

## Scripts

| Script | What it does |
| ------ | ------------ |
| `scripts/import_workflows.sh [file]` | imports every workflow (or one file) into the running container with the n8n CLI |
| `scripts/export_workflows.sh` | exports every workflow from n8n to `backups/workflows/<timestamp>/` |
| `scripts/backup_n8n.sh` | backs up n8n's data directory and database |

The import and export scripts take the container name from `N8N_CONTAINER`
(default `open-security-automations`). They used n8n's REST API with HTTP
basic auth before, which n8n 1.x answers with 401.

## Standalone development

`docker-compose.yml` in this directory runs n8n on its own, for working on
workflows; its settings are in `.env.example`. The supported deployment is
the `automations` profile of the root `docker-compose.yml`.
