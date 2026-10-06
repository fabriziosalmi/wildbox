# Guardian Service API

Guardian is the Django REST Framework service that stores assets, vulnerabilities,
scanner records, remediation work, compliance data, integrations and reports. This
page lists the routes defined in `open-security-guardian/guardian/urls.py` and in
each app's `urls.py`, and how to reach them through the gateway.

In the examples, `<host>` is the name you reach the gateway by, and IDs and
credentials are placeholders.

## Table of Contents

- [Base URL and routing](#base-url-and-routing)
- [Authentication and permissions](#authentication-and-permissions)
- [Conventions](#conventions)
- [Assets](#assets)
- [Vulnerabilities](#vulnerabilities)
- [Scanners, scans and schedules](#scanners-scans-and-schedules)
- [Remediation](#remediation)
- [Compliance](#compliance)
- [Integrations](#integrations)
- [Reports and alerts](#reports-and-alerts)
- [Task status](#task-status)
- [Health check](#health-check)
- [Rate limits](#rate-limits)
- [Errors](#errors)

---

## Base URL and routing

Every request goes through the gateway:

```text
https://<host>/api/v1/guardian/<path>  ->  guardian /api/v1/<path>
```

The gateway strips `/api/v1/guardian/` and forwards the rest to guardian under
`/api/v1/`. A few details of that route matter to clients:

- **Trailing slashes are required.** Every guardian route ends with `/`. Without it,
  Django's `APPEND_SLASH` answers `301 Moved Permanently` to the same path with the
  slash. The gateway rewrites that `Location` header back to `/api/v1/guardian/...`,
  so a `GET` that follows redirects still works, but most clients resend a
  redirected `POST` as a `GET`. Always write the slash.
- **Guardian sees its own host name.** The gateway sends `Host: open-security-guardian`
  (the caller's host travels as `X-Forwarded-Host`), because Django checks `Host`
  against `ALLOWED_HOSTS`. Guardian puts neither name in its answers: the `next` and
  `previous` links of a paginated response are relative references under
  `/api/v1/guardian/` (see [Pagination](#pagination)). The gateway tells guardian
  that path in `X-Forwarded-Prefix`, which it sets itself on every request, replacing
  any value a client sends.
- Paths in the tables below are relative to `https://<host>/api/v1/guardian/`.

Set up a shell for the examples:

```bash
CA=open-security-gateway/ssl/wildbox.crt
BASE="https://<host>/api/v1/guardian"
```

---

## Authentication and permissions

The gateway authenticates every request before it reaches guardian, then passes the
caller's user, team and role to guardian in trusted headers. Use either credential:

- **JWT bearer token.** Sign in with `POST https://<host>/auth/jwt/login`
  (form-encoded `username` and `password`) and send the `access_token` as
  `Authorization: Bearer <token>`.
- **API key.** Create one with the identity service:
  `POST /api/v1/identity/api-keys` (a user key) or
  `POST /api/v1/identity/teams/{team_id}/api-keys` (a team key). Send it as
  `X-API-Key: <key>`. See the [Identity Service API](../identity/endpoints.md).
  Guardian has no API keys of its own: the ones it had, and the model that stored
  them, were removed (#633).

```bash
TOKEN=$(curl -s --cacert "$CA" -X POST "https://<host>/auth/jwt/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "username=analyst@example.com" \
  --data-urlencode "password=<password>" | jq -r .access_token)

curl -s --cacert "$CA" "$BASE/assets/assets/" \
  -H "Authorization: Bearer $TOKEN"
```

### Gateway only

Guardian accepts a request under `/api/` only when it carries the gateway's
`X-Wildbox-User-ID` and `X-Wildbox-Team-ID` headers together with
`X-Gateway-Secret`, the `GATEWAY_INTERNAL_SECRET` proof of origin
(`apps/core/gateway_middleware.py`). A request sent to guardian's own port is
refused, whatever key it carries:

- without the identity headers: `403` with
  `"code": "GATEWAY_AUTH_REQUIRED"`;
- with the identity headers but without the matching secret: `403` with
  `"code": "GATEWAY_SECRET_REQUIRED"`;
- when guardian itself has no `GATEWAY_INTERNAL_SECRET`: `503` with
  `"code": "GATEWAY_SECRET_NOT_CONFIGURED"`.

With `DEBUG` false guardian redirects plain HTTP to HTTPS before it looks at
any of this (`SECURE_SSL_REDIRECT` in `guardian/settings.py`), so a request
sent to port 8013 without `X-Forwarded-Proto: https` answers `301`, not
`403`. The gateway sends that header on every request.

Django REST Framework authenticates with the gateway headers only
(`GatewayHeaderAuthentication` in `guardian/settings.py`). Before #633 guardian
also accepted its own API keys in `X-API-Key` on its port, as an administrator,
beside the gateway.

### API key scopes

When an API key carries scopes, the gateway checks them on every guardian request
(`required_scope_for_request` in `open-security-gateway/nginx/lua/auth_handler.lua`).
A key created without scopes is unrestricted; a key with the `admin` scope passes
every check.

| Request | Required scope | Also accepted |
| --- | --- | --- |
| `GET`, `HEAD`, `OPTIONS` | `data:read` | `data:write`, `read`, `write` |
| `POST`, `PUT`, `PATCH` | `data:write` | `write` |
| `DELETE` | `data:delete` | none |

A key without the required scope gets `403` with `"error": "insufficient_scope"`.

guardian checks the same scope again on what the gateway forwards about the
credential (`X-Wildbox-Auth-Type` and `X-Wildbox-Scopes`), in
`GatewayAuthMiddleware`. A request the gateway should not have let through
answers `403` with `"code": "INSUFFICIENT_SCOPE"` and the `required_scope`;
one that carries the gateway's secret without `X-Wildbox-Auth-Type` answers
`403` with `"code": "GATEWAY_AUTH_TYPE_REQUIRED"`. In a view, `request.auth`
is the caller as the gateway described it, with `auth_type`, `scopes` and
`has_scope("data:delete")`.

### Roles

Guardian applies the team role it receives from the gateway
(`apps/core/permissions.py`):

- Any authenticated member can read (`GET`, `HEAD`, `OPTIONS`).
- Only `owner` and `admin` can create, change or delete. A `member` gets `403`.
- On the vulnerability list and detail routes, a `member` sees only vulnerabilities
  assigned to them or created by them; `owner` and `admin` see all of them.

### Teams

Every request acts on the caller's team's data only, the team the gateway
reports in `X-Wildbox-Team-ID` (`apps/core/tenancy.py`):

- Lists return the team's rows. Another team's id answers `404` on every
  detail route and action, as an id that does not exist would.
- A new row belongs to the caller's team; a `team_id` in the body is ignored.
  A reference to another team's row (an asset, a scanner, a user) is refused
  as one that does not exist.
- Rows that hang off another row take its team: a vulnerability its asset's,
  a scan its scanner's.
- Compliance frameworks, their controls and vulnerability templates without a
  team are shared reference data: every team reads them and none changes them.
- Names are unique within a team (environments, asset groups, discovery
  rules, frameworks, vulnerability templates, webhook endpoint paths): a
  name another team uses is free, and the answer to a duplicate never says
  what another team has.
- A user can be assigned or named (an assignee, an owner, an approver, the
  people a dashboard is shared with) only while they are a member of the
  team: they have made a request as a member of it within the last 30 days
  (`GUARDIAN_TEAM_MEMBERSHIP_MAX_AGE_DAYS`), and identity has not removed
  them from it. A user who left is refused as an id that does not exist
  is, and the roles they held in the team are cleared when they are
  removed: a vulnerability assigned to them becomes unassigned, with a
  line in its history. What they did (the rows they created, the notes
  they wrote) stays attributed to them. A member who is removed from a
  team and added back within ten minutes can use guardian at once, but can
  be named again only once the ten minutes have passed and they have made
  a request: for that long guardian does not take a request as proof of
  the membership, since one sent before the removal may arrive after it.
- `/api/v1/guardian/tasks/<uuid>/` answers only for tasks the team
  dispatched; any other id answers `404`.

Rows created before 0.11.0 have no team and no team sees them until an
operator assigns them, for example with
`docker compose exec guardian python manage.py assign_guardian_team --team <team UUID>`
([UPGRADING.md, section 39](https://github.com/fabriziosalmi/wildbox/blob/main/UPGRADING.md#39-guardian-keeps-each-team-to-its-own-data-assign-the-existing-rows-required)).

---

## Conventions

### Representation

Every answer is JSON, errors included. A request whose `Accept` header admits only
something else (`Accept: text/html`) answers `406`; a browser, which also sends
`*/*`, gets the JSON. Django REST framework's browsable API, the HTML pages with a
form for each route, is served only when guardian runs with `DEBUG=true`, like the
schema and its UIs. Before #724 it was on in every environment, and in the image
every request for `text/html` answered `500`.

### Pagination

List routes use page-number pagination with 50 items per page. Pass `?page=N` for
another page and `?page_size=N` for another size, from 1 to 200: a larger value is
served 200 items, and a value that is not a positive whole number is served the
default 50. To read only how many records a list has, ask for `?page_size=1` and
read `count`. Before #724 `page_size` was ignored.

```json
{
  "count": 120,
  "next": "/api/v1/guardian/assets/assets/?page=2",
  "previous": null,
  "results": []
}
```

`next` and `previous` are relative references: the path and query of the neighboring
page, without scheme or host, or `null` when there is none. They keep the other
query parameters of the request (`page_size`, `search`, `ordering`, filters);
`previous` for page 2 is the list without `page`. Resolve a link against the URL you requested, as you
would a redirect:

```python
import requests
from urllib.parse import urljoin

url = "https://<host>/api/v1/guardian/assets/assets/?ordering=name"
while url:
    response = requests.get(url, headers={"X-API-Key": "<key>"}, timeout=30)
    response.raise_for_status()
    page = response.json()
    for asset in page["results"]:
        print(asset["name"])
    url = urljoin(response.url, page["next"]) if page["next"] else None
```

In JavaScript, `new URL(page.next, response.url)` does the same. Before #643 the
links were absolute URLs on `open-security-guardian`, the Host the gateway presents
guardian, and without the `/guardian` segment: no client could follow them. The
links contain no host on purpose: the only host guardian could write is the one the
client sent the gateway.

Custom actions that return a set of records (for example a vulnerability's
`history/`, or `compliance/exceptions/pending/`) answer a plain JSON array, not a
page. The one paginated custom action is `reports/alerts/{id}/notifications/`.

### Search, ordering and filters

Most list routes accept:

- `?search=<text>`: searches the fields the view declares (for example asset
  `name`, `hostname`, `fqdn`, `ip_address` and `description`), without regard to
  case. Every word of the text must be found, each in any of the fields.
- `?ordering=<field>` or `?ordering=-<field>`: sorts by one of the view's ordering
  fields. A field the view does not order by is ignored.
- Field filters from the view's filter set, for example `?status=active` or
  `?criticality=high` on assets, and `?severity=critical` or `?status=open` on
  vulnerabilities. The filters of the asset and vulnerability lists are in their
  sections below.

Several filters together select the records that match all of them. A value a
filter does not accept (a severity that does not exist, the id of a record of
another team) answers `400` with the filter's name; a parameter the list does not
have is ignored. A true/false filter takes `true` or `false`: `true` selects the
records that are so, `false` the others.

`?format=` does not choose the representation of the answer, which is JSON; on
`reports/reports/` it is the filter on a report's format. Before #724 it was read
as the name of a renderer on every route, so `reports/reports/?format=pdf`
answered `404`.

### IDs and methods

`{id}` is the record's primary key; assets and vulnerabilities use UUIDs. Each
resource in the tables supports the standard routes unless the table says
otherwise:

| Method | Path | Action |
| --- | --- | --- |
| `GET` | `<resource>/` | List (paginated) |
| `POST` | `<resource>/` | Create |
| `GET` | `<resource>/{id}/` | Retrieve |
| `PUT`, `PATCH` | `<resource>/{id}/` | Update |
| `DELETE` | `<resource>/{id}/` | Delete |

Custom actions keep the Python method name in their path, underscores included
(for example `cleanup_logs/`, `run_now/`).

### What an action's answer means

An action answers `2xx` only for something it did: a row it stored, changed or
deleted, or a task it queued. Guardian served twenty actions that answered
`{"status": "success", ...}`, or fixed figures, without doing anything (testing a
connection, starting a scan, importing results, sending a notification,
synchronizing a ticket). They were removed in
[#644](https://github.com/fabriziosalmi/wildbox/issues/644): their routes answer
`404`, and each section below says what is left in their place. Guardian does not
contact external scanners, ticketing systems, webhooks or notification channels.

What guardian cannot do for a record that exists answers an error with a stable
`code`, never a success: for example `501` with
`"code": "DISCOVERY_TYPE_NOT_IMPLEMENTED"` when a discovery rule of a type without
an implementation is run.

---

## Assets

Prefix: `assets/`. Defined in `apps/assets/urls.py`.

| Resource | Path | Notes |
| --- | --- | --- |
| Assets | `assets/assets/` | Standard routes |
| Environments | `assets/environments/` | Standard routes |
| Business functions | `assets/business-functions/` | Standard routes |
| Asset groups | `assets/groups/` | Standard routes |
| Discovery rules | `assets/discovery-rules/` | Standard routes |
| Installed software | `assets/software/` | Standard routes |
| Ports | `assets/ports/` | Standard routes |

Custom actions:

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `assets/assets/{id}/scan/` | Queues a port scan of the asset's `ip_address`. Returns `message` and `task_id`; `400` with `error` if the asset has no IP address, or has an [internal one](#scan-targets), and then nothing is queued |
| `POST` | `assets/assets/{id}/add_software/` | Adds a software record to the asset (`201`) |
| `POST` | `assets/assets/{id}/add_port/` | Adds a port record to the asset (`201`) |
| `POST` | `assets/assets/{id}/add_tag/` | Body `{"tag": "..."}` |
| `DELETE` | `assets/assets/{id}/remove_tag/` | Body `{"tag": "..."}` |
| `POST` | `assets/assets/discover/` | Body `{"network_range": "192.0.2.0/24", "scan_type": "basic"}`; queues a discovery of that network and returns `task_id`. `network_range` is a network in CIDR notation, or one address, of at most 1,024 addresses (a `/22` of IPv4); `scan_type` is `basic` (the default) or `comprehensive`, which also scans the ports of the hosts found. Anything else answers `400` on that field and queues nothing, and so does a network with an [internal address](#scan-targets) in it |
| `GET` | `assets/assets/statistics/` | Totals by type, criticality and status |
| `POST` | `assets/groups/{id}/apply_rules/` | Applies the group's assignment rules |
| `POST` | `assets/groups/{id}/add_assets/` | Adds assets to the group |
| `DELETE` | `assets/groups/{id}/remove_assets/` | Removes assets from the group |
| `POST` | `assets/discovery-rules/{id}/execute/` | Queues a run of the rule and returns `task_id`. `400` if the rule is disabled; `501` with `"code": "DISCOVERY_TYPE_NOT_IMPLEMENTED"` for a rule whose `discovery_type` is not `network_scan` (one stored before the API refused the other types) |
| `POST` | `assets/discovery-rules/{id}/enable/` | Enables the rule. `501` with `"code": "DISCOVERY_TYPE_NOT_IMPLEMENTED"` for a rule whose `discovery_type` is not `network_scan`: it would never run |
| `POST` | `assets/discovery-rules/{id}/disable/` | Disables the rule |
| `GET` | `assets/software/inventory/` | Software inventory across assets |
| `GET` | `assets/ports/summary/` | Port summary across assets |

A rule is `enabled` when it runs on its schedule. A rule of a type guardian does
not implement (one stored before the API refused the other types) never runs, so it
cannot be enabled: `enable/` answers `501` and a `PATCH` with `"enabled": true`
answers `400` on `enabled`. The upgrade to this version switches off the ones that
were stored as enabled (#724).

A discovery rule of type `network_scan` lists what it sweeps in
`target_specification`: `networks`, 1 to 32 networks in CIDR notation, each of at
most 1,024 addresses, and optionally `scan_type` (`basic` or `comprehensive`). The
bound is the one the tools service puts on a scan target. Before #724 neither
`discover/` nor a rule checked the size of a network, and `discover/` did not check
that `network_range` was one. A rule stored with a larger network keeps it, and
its runs skip that network.

Filters of `assets/assets/`:

| Parameter | Selects |
| --- | --- |
| `asset_type`, `criticality`, `status` | The value given; repeat the parameter for any of several (`?status=active&status=maintenance`) |
| `environment`, `business_function` | Assets whose environment or business function has a name that contains the text |
| `owner` | Assets whose owner's user name contains the text |
| `tags` | Assets that have every tag of a comma-separated list |
| `ip_range` | Assets whose `ip_address` is in a network (`10.20.0.0/16`) or is the address given. An IPv4 network of any size; an IPv6 network of at most 256 addresses (`/120`), `400` for a larger one. A value that is not a network is the start of an address: `?ip_range=10.20.` |
| `discovered_after`, `discovered_before` | `first_discovered` on or after, on or before, a date and time (ISO 8601) |
| `last_seen_after`, `last_seen_before` | The same for `last_seen` |
| `has_vulnerabilities`, `has_software`, `has_open_ports` | `true` or `false` |

Asset fields accepted on create include `name` (required), `description`,
`asset_type` (`server`, `workstation`, `network_device`, `mobile_device`,
`iot_device`, `cloud_instance`, `container`, `application`, `database`, `other`),
`status` (`active`, `inactive`, `decommissioned`, `maintenance`, `unknown`),
`ip_address`, `hostname`, `fqdn`, `criticality` (`critical`, `high`, `medium`, `low`,
`unknown`), `tags` and `metadata`. Two assets of the same team cannot share an
`ip_address` (`400` on `ip_address`); an address another team uses is free. Creating
an asset that has an `ip_address` and no ports also queues a port scan, unless the
address is an [internal one](#scan-targets).

```bash
curl -s --cacert "$CA" -X POST "$BASE/assets/assets/" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "web-01", "asset_type": "server", "criticality": "high", "hostname": "web-01.example.com"}'

curl -s --cacert "$CA" "$BASE/assets/assets/?criticality=high&ordering=name" \
  -H "Authorization: Bearer $TOKEN"
```

### Scan targets

Guardian's worker connects to what a discovery or a port scan names, and it runs
inside the stack's networks. So an internal address is not scanned (since #748):

- **Refused**: private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback,
  link-local, multicast, reserved, shared (`100.64.0.0/10`) and documentation
  addresses, the cloud metadata addresses, and the IPv6 ranges of the same kinds,
  an IPv4 address written inside an IPv6 one included (`::ffff:10.0.0.1`).
- **A network is refused whole** when any address of it is internal: `203.0.112.0/22`
  is refused for the `/24` at `203.0.113.0`.
- **Where**: `discover/` answers `400` on `network_range`; creating or changing a
  discovery rule answers `400` on `target_specification`; `scan/` answers `400` with
  `error`. Nothing is queued. The worker checks again when the task runs: a rule or
  an asset stored before this version keeps its network or address, and its runs
  skip it.
- **An asset is still recorded.** `POST assets/assets/` accepts any `ip_address`, as
  an inventory must; an asset at an internal address is not port scanned when it is
  created.

The refusal says what to ask for:

```json
{"network_range": ["10.0.0.0/24 includes 10.0.0.0, an internal address (private, loopback, link-local, multicast, reserved or cloud metadata). guardian scans an internal address only if the operator of this deployment lists its range in GUARDIAN_ALLOWED_INTERNAL_TARGETS."]}
```

`GUARDIAN_ALLOWED_INTERNAL_TARGETS` is the operator's setting, empty by default; a
network is then accepted when every internal address of it is inside a listed range.
See [Internal targets of Guardian's scans](../../guides/deployment.md#internal-targets-of-guardians-scans).
The tools service applies the same policy to its network tools, with a setting of
its own.

---

## Vulnerabilities

Prefix: `vulnerabilities/`. The vulnerability resource is registered at the root of
the prefix, so the list is `vulnerabilities/` itself.

| Resource | Path | Notes |
| --- | --- | --- |
| Vulnerabilities | `vulnerabilities/` | Standard routes; `member` sees only assigned or self-created records |
| Templates | `vulnerabilities/templates/` | Standard routes |
| Risk assessments | `vulnerabilities/assessments/` | Standard routes |

Custom actions:

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `vulnerabilities/{id}/assign/` | Body `assigned_to` (user ID) and/or `assignee_group`; `400` with neither. Queues the assignment e-mail (see below) |
| `POST` | `vulnerabilities/{id}/close/` | Sets status `resolved`. Body `reason`, `resolution_method` (default `fixed`). Adds a history entry with the reason and the status the vulnerability had |
| `POST` | `vulnerabilities/{id}/reopen/` | Sets status `open` and clears `resolved_at`. Body `reason`. Adds a history entry with the reason and the status the vulnerability had |
| `POST` | `vulnerabilities/{id}/add_tag/` | Body `{"tag": "..."}` |
| `POST` | `vulnerabilities/{id}/remove_tag/` | Body `{"tag": "..."}` (a `POST` here, unlike assets) |
| `GET` | `vulnerabilities/{id}/history/` | Change history, as a plain array. The SLA check and the assignment notification record here what became of their e-mail: `SLA violation notification sent`, `sent to the team's owners and admins (no assignee to e-mail)` or `not sent (<reason>)` (`field_name` `sla_status`), and `Assignment notification sent` or `not sent (<reason>)` (`field_name` `assignment_notification`) |
| `POST` | `vulnerabilities/bulk_action/` | See below |
| `GET` | `vulnerabilities/stats/` | Counts by severity and status of the vulnerabilities the list's filters select |
| `GET` | `vulnerabilities/trends/` | Daily counts for today and the `?days=N` days before it (default 30, from 0 to 366; `400` otherwise). See below |

Removed in #724: `GET vulnerabilities/{id}/attachments/`, which answers `404`.
Guardian has no way to attach a file to a vulnerability (there was never an upload
route), so the list was always empty, and the `file` of an attachment would have
been a `/media/` URL that nothing serves. Record the location of evidence in the
vulnerability's `evidence` or `references` fields.

A vulnerability needs `title`, `description` and `asset` (an asset ID); `cve_id`
is optional (before #724 a request without it answered `400`, so send `"cve_id":
""` to an older guardian). Guardian keeps one finding for an asset, a CVE and a
port: a second one with the same `port` answers `400`. The rule does not hold
when `port` is omitted: two findings for the same asset and CVE without a
port are both accepted. The answer to the creation carries the new
record's `id` (since #724). `severity`
is one of `critical`, `high`, `medium`, `low`, `info`; `status` is one of `open`,
`in_progress`, `resolved`, `accepted`, `false_positive`, `duplicate`; `priority` is
one of `p1` to `p4`. `cvss_v3_score` must be between 0.0 and 10.0.

`resolved_at` is the time the status became `resolved`. Guardian writes it, on
any change of status: `close/`, a `PATCH` or `PUT` of `status`, a bulk action. It
is cleared when the status stops being `resolved`. Before #724 only `close/` and
`reopen/` wrote it, so a vulnerability resolved by a `PATCH` had none and was
missing from the resolution figures of `stats/` and `trends/`.

A user who is assigned a vulnerability is sent an e-mail, whichever way the
assignment is made: `assign/`, `bulk_action/` with `assign`, or a `PUT` or `PATCH`
that changes `assigned_to` (the last two since #724). It goes to the address
identity has for the assignee, while they are a member of the team, and the
vulnerability's history says what became of it. An assignment to a group alone
sends nothing, and so does creating a vulnerability that already names its
assignee.

Filters of `vulnerabilities/`, which `vulnerabilities/stats/` takes too:

| Parameter | Selects |
| --- | --- |
| `severity`, `status`, `priority`, `threat_level` | The value given; repeat the parameter for any of several (`?severity=critical&severity=high`). `threat_level` is one of `imminent`, `active`, `emerging`, `possible`, `unknown` |
| `risk_score_min`, `risk_score_max` | `risk_score` at least, at most, a number |
| `cvss_min`, `cvss_max` | `cvss_v3_score` at least, at most, a number |
| `asset_id` | Vulnerabilities of one asset |
| `asset_name` | The asset's name contains the text |
| `asset_type`, `asset_criticality` | The asset's type or criticality, without regard to case |
| `asset_environment` | The name of the asset's environment, without regard to case |
| `assigned_to` | The user ID of the assignee |
| `assignee_group` | The group contains the text |
| `unassigned` | `true`: neither a user nor a group is assigned. `false`: one of them is |
| `discovered_after`, `discovered_before` | `first_discovered` on or after, on or before, a date and time (ISO 8601) |
| `due_date_from`, `due_date_to` | `due_date` on or after, on or before, a date and time |
| `overdue`, `due_today`, `due_this_week` | `true`: status `open` and due before now, today, or within the next seven days. `false`: the others |
| `cve_id`, `scanner`, `service` | The field contains the text |
| `has_tag` | Vulnerabilities that have the tag |
| `port`, `protocol` | The port number; the protocol, without regard to case |

`?search=` reads `title`, `description`, `cve_id`, the asset's `name` and
`ip_address`, `scanner` and `service`.

Before #724 the four filters of the first row matched no record, so
`?severity=medium` and `?status=open` answered an empty list (and `stats/`
zeros); `asset_environment` answered `500`; `unassigned=true` matched no record;
`false` on a true/false filter was ignored; and a search had to match in `title`,
`description`, `cve_id` or the asset's name even when it also matched the
address, the scanner or the service.

`bulk_action/` takes `vulnerability_ids` (1 to 100 UUIDs) and `action`, one of:

| `action` | Also takes | Effect on each vulnerability |
| --- | --- | --- |
| `close` | `reason` (optional) | As `close/` |
| `reopen` | `reason` (optional) | As `reopen/` |
| `assign` | `assigned_to` and/or `assignee_group` | Sets the ones given and leaves the other as it was. With `assigned_to`, queues the assignment e-mail for each vulnerability, as `assign/` does |
| `tag` | `tag` | Adds the tag |
| `untag` | `tag` | Removes the tag |
| `priority` | `priority` (`p1` to `p4`) | Sets the priority |

The response reports `updated_count`, the number of the team's vulnerabilities
among the ids; `404` if none of them is. Any other `action` answers `400`.
Before #644, `reopen` and `untag` were accepted and answered
`"Bulk action completed on 0 vulnerabilities"`.

`trends/` counts the vulnerabilities the list would show the caller: the team's,
and for a `member` only those assigned to or created by them. It takes `days` and
none of the list's filters. Each day has `discovered_count` and `resolved_count`
(vulnerabilities first discovered, and resolved, on that day), `total_open`, the
vulnerabilities whose status was `open` when that day ended, and
`avg_risk_score`, the average of the risk score those had then.

The last two are read from the vulnerabilities' history, which records every
change of status and of risk score. Before #724 they described the vulnerabilities
whose status is `open` now, so one resolved yesterday was open on no earlier day.
What the history cannot say: a vulnerability deleted since is not counted on the
days it existed, and a status changed without a history entry (by a direct write
to the database) shows from the day the figure is asked for. Guardian keeps a
year of history, which is also the longest window.

```bash
curl -s --cacert "$CA" "$BASE/vulnerabilities/?severity=critical&status=open" \
  -H "Authorization: Bearer $TOKEN"

curl -s --cacert "$CA" -X POST "$BASE/vulnerabilities/<vulnerability-id>/close/" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reason": "Patched in release 2.4", "resolution_method": "fixed"}'
```

---

## Scanners, scans and schedules

Prefix: `scanners/`. These routes record external scanners and their runs. Guardian
does not contact an external scanner: it cannot test a connection to one, start,
stop, pause or resume a scan on one, or import its results. The only scan it
performs itself is the asset port scan (`assets/assets/{id}/scan/`).

| Resource | Path | Notes |
| --- | --- | --- |
| Scanners | `scanners/scanners/` | Standard routes; filters `scanner_type`, `status` |
| Scan profiles | `scanners/scan-profiles/` | Standard routes; filter `scanner` |
| Scans | `scanners/scans/` | Standard routes; filters `scanner`, `profile`, `status` |
| Scan results | `scanners/scan-results/` | Standard routes; filters `scan`, `severity`, `processed`, `vulnerability_created` |
| Scan schedules | `scanners/scan-schedules/` | List, retrieve and delete only; see below |

Custom actions:

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `scanners/scanners/stats/` | Scanner and scan counts |
| `GET` | `scanners/scans/{id}/results/` | Results of one scan, as a plain array |
| `POST` | `scanners/scan-schedules/{id}/disable/` | Disables a schedule |

Removed in #644, because they answered `success` without contacting a scanner:

| Removed route | Now answers | Use instead |
| --- | --- | --- |
| `POST scanners/scanners/{id}/test_connection/` | `404` | Nothing: guardian cannot reach a scanner. The action required the caller to send a `success` flag and answered `Connection test passed` whatever it was |
| `POST scanners/scans/{id}/start/`, `stop/`, `pause/`, `resume/` | `404` | A scan's `status` is a field of the record: `PATCH scanners/scans/{id}/` with `{"status": "running"}` (`pending`, `running`, `completed`, `failed`, `cancelled` or `paused`). `stop/` stored `stopped`, which is not one of them |
| `POST scanners/scans/import_results/` | `405` | Record the findings yourself: `POST scanners/scan-results/` for a scan's results, `POST vulnerabilities/` for vulnerabilities |

### A scanner has no stored credential

A scanner record says where the scanner is (`base_url`, `username`,
`verify_ssl`), not how to log in to it. `api_key` and `password` were fields of
the record until
[issue #728](https://github.com/fabriziosalmi/wildbox/issues/728): guardian
accepted them, kept them in its database as plain text and never returned them,
and nothing used them, because guardian does not connect to a scanner. Both
fields are gone, with the values that were stored.

A `POST`, `PUT` or `PATCH` to `scanners/scanners/` that sends a value in either
field answers `400` on that field and stores nothing, so a client never
believes guardian holds a credential it discarded:

```json
{
  "api_key": [
    "guardian does not store scanner credentials: it has no code that connects to a scanner, so nothing would use one. Leave this field out."
  ]
}
```

An empty value (`""`, `null`) is ignored, like a field guardian does not know.
Do not put a credential in a free-form field instead (`metadata`, `tags`,
`description`, a profile's `advanced_settings`, a scan's `scan_settings`):
those are stored as sent and returned to every member of the team.

### Scan schedules are not supported

Because guardian cannot start a scan on an external scanner, a scan schedule would
never run, and the API offers no way to make one, change one, run one or switch one
on. A schedule stored by an earlier version can be listed and read
(`GET scanners/scan-schedules/`, `GET .../{id}/`), disabled
(`POST .../{id}/disable/`) and deleted (`DELETE .../{id}/`).

The routes that are not there answer as any missing route does:

| Request | Answer |
| --- | --- |
| `POST scanners/scan-schedules/` | `405`, `Allow: GET, HEAD, OPTIONS` |
| `PUT` or `PATCH scanners/scan-schedules/{id}/` | `405`, `Allow: GET, DELETE, HEAD, OPTIONS` |
| `POST scanners/scan-schedules/{id}/trigger/` | `404` |
| `POST scanners/scan-schedules/{id}/enable/` | `404` |

From #548 to #724 these four were routed and answered
`400 {"detail": "Scheduled scans are not supported: ..."}` to every request. A
client that treated that `400` as "not supported" should treat `404` and `405`
the same way.

---

## Remediation

Prefix: `remediation/`.

| Resource | Path | Notes |
| --- | --- | --- |
| Tickets | `remediation/tickets/` | Standard routes |
| Workflows | `remediation/workflows/` | Standard routes |
| Steps | `remediation/steps/` | Standard routes |
| Comments | `remediation/comments/` | Standard routes |
| Templates | `remediation/templates/` | Standard routes |

Custom actions:

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `remediation/tickets/{id}/assign/` | Body `{"assignee_id": <user ID>}`. Sets the ticket's `assigned_to` to that member of the team and returns it; `400` if the user is not one |
| `POST` | `remediation/tickets/{id}/update_status/` | Body `{"status": "..."}`; sets the ticket status. `400` with the `valid` values for any other (`pending`, `assigned`, `in_progress`, `testing`, `completed`, `verified`, `rejected`, `deferred`) |
| `POST` | `remediation/workflows/{id}/start/` | Sets the status to `in_progress`, sets `actual_start_date` if it has none and clears `actual_completion_date` |
| `POST` | `remediation/workflows/{id}/complete/` | Sets the status to `completed` and `actual_completion_date` to now |
| `GET` | `remediation/workflows/{id}/progress/` | Progress of the workflow's steps |
| `POST` | `remediation/steps/{id}/execute/` | Marks the step started, by the caller. Runs nothing: `automation_script` is text for the person doing the step |
| `POST` | `remediation/steps/{id}/complete/` | Marks the step completed; optional `notes`, `validation_results` |
| `POST` | `remediation/steps/{id}/skip/` | Marks the step skipped |
| `POST` | `remediation/templates/{id}/clone/` | Stores a copy of the template and returns it (`201`). Optional `name`; otherwise the original's name, a space and `(copy)`. The copy's `usage_count` and `success_rate` start at 0 |
| `POST` | `remediation/templates/{id}/apply/` | Creates the remediation workflow of a vulnerability from the template and returns it (`201`). See below |
| `GET` | `remediation/templates/categories/` | Template categories in use |

`apply/` takes `vulnerability_id`, one of the team's vulnerabilities, and an
optional `title` (otherwise `<template name>: <vulnerability title>`). The workflow
gets the template's `remediation_type`, `default_priority`, effort estimate,
rollback and testing plans, and one step per entry of `step_templates` (`title`,
`description`, `instructions`, `validation_criteria`, `estimated_duration_minutes`,
`automation_script`), in order; the template's `usage_count` goes up by one. It
answers:

- `400` with `{"error": "Vulnerability not found"}` for an id that is not one of
  the team's vulnerabilities;
- `400` with `"code": "TEMPLATE_STEPS_INVALID"` when `step_templates` is not a list
  of objects with those fields, and creates nothing;
- `409` with `"code": "WORKFLOW_EXISTS"` when the vulnerability already has a
  workflow (it has at most one).

Removed in #644:

| Removed route | Now answers | Use instead |
| --- | --- | --- |
| `POST remediation/tickets/{id}/sync_external/` | `404` | Nothing: guardian does not talk to the ticketing system. A ticket is a record you keep up to date with `PATCH remediation/tickets/{id}/` |
| `POST remediation/workflows/{id}/pause/` | `404` | `PATCH remediation/workflows/{id}/` with `{"status": "deferred"}`. `pause/` stored `paused`, a status workflows do not have: the API then refused it on `PUT` and as a filter. A workflow it left `paused` keeps that value until you set another |

---

## Compliance

Prefix: `compliance/`.

| Resource | Path | Notes |
| --- | --- | --- |
| Frameworks | `compliance/frameworks/` | Standard routes |
| Controls | `compliance/controls/` | Standard routes |
| Assessments | `compliance/assessments/` | Standard routes |
| Evidence | `compliance/evidence/` | Standard routes |
| Results | `compliance/results/` | Standard routes |
| Exceptions | `compliance/exceptions/` | Standard routes |
| Metrics | `compliance/metrics/` | Read-only (list and retrieve) |

Custom actions (all `GET`):

| Path | Description |
| --- | --- |
| `compliance/frameworks/{id}/controls/` | Controls of a framework |
| `compliance/frameworks/{id}/assessments/` | Assessments of a framework |
| `compliance/frameworks/{id}/metrics/` | Latest metrics of a framework |
| `compliance/controls/{id}/results/` | Assessment results for a control |
| `compliance/controls/{id}/evidence/` | Evidence for a control |
| `compliance/assessments/{id}/results/` | Results of an assessment |
| `compliance/assessments/{id}/evidence/` | Evidence of an assessment |
| `compliance/assessments/{id}/summary/` | Compliance summary of an assessment |
| `compliance/assessments/overdue/` | Overdue assessments |
| `compliance/results/non_compliant/` | Non-compliant results |
| `compliance/results/high_risk/` | High-risk results |
| `compliance/exceptions/pending/` | Pending exceptions |
| `compliance/exceptions/expiring_soon/` | Exceptions expiring in the next 30 days |
| `compliance/exceptions/needs_review/` | Exceptions due for review |
| `compliance/metrics/dashboard/` | Dashboard metrics |

---

## Integrations

Prefix: `integrations/`. These are records: guardian stores them and does nothing
with them. It does not contact an external system, run a synchronization, receive
or send a webhook, or deliver through a notification channel, and nothing writes
integration logs. The notifications guardian does send (alert rules,
scheduled reports, SLA violations, vulnerability assignments, compliance
notifications) are e-mails: to the addresses the alert rule or the report
schedule names, to the vulnerability's assignee, and otherwise to the owners
and admins of the team (always for a compliance notification, which names
nobody; never for an assignment). None uses a notification channel.

| Resource | Path | Notes |
| --- | --- | --- |
| External systems | `integrations/systems/` | Standard routes; filters `system_type`, `status`, `auth_type` |
| Field mappings | `integrations/mappings/` | Standard routes |
| Sync records | `integrations/sync-records/` | Standard routes |
| Webhook endpoints | `integrations/webhooks/` | Standard routes. `endpoint_url` is a record of the path the team chose, unique within the team (`400` on `endpoint_url` for a path one of the team's endpoints already uses); guardian does not receive webhooks on it |
| Integration logs | `integrations/logs/` | Read-only (list and retrieve) |
| Notification channels | `integrations/notifications/` | Standard routes |

Custom action:

| Method | Path | Description |
| --- | --- | --- |
| `DELETE` | `integrations/logs/cleanup_logs/` | Deletes the team's integration logs older than `?older_than_days=N` (default 30; a whole number from 1 to 36500, `400` otherwise). Returns `{"deleted": <rows>, "older_than_days": N}`. `owner` or `admin` only |

Removed in #644. Each answered a fixed success, or fixed figures, whatever the
record and without contacting anything; all now answer `404`:

| Removed route | It answered | Use instead |
| --- | --- | --- |
| `POST integrations/systems/{id}/test_connection/` | `"Connection test completed"` | Nothing: guardian contacts no external system |
| `POST integrations/systems/{id}/health_check/` | `{"status": "healthy", "response_time_ms": 150}` | Nothing. `status` and `last_health_check` on the record are what you store there |
| `GET integrations/systems/{id}/sync_status/` | `"status": "active"` and the record's `last_sync` | `GET integrations/systems/{id}/` for `last_sync` |
| `POST integrations/mappings/{id}/test_mapping/`, `sync_now/` | `"Mapping test completed"`, `"Sync initiated"` | Nothing: there is no synchronization |
| `GET integrations/sync-records/sync_statistics/` | Zeros | `GET integrations/sync-records/?sync_status=failed` (or `success`, `pending`, ...) and read `count` |
| `POST integrations/sync-records/{id}/retry_sync/` | `"Sync retry initiated"` | Nothing |
| `POST integrations/webhooks/{id}/test_webhook/`, `trigger_webhook/` | `"Webhook test completed"`, `"Webhook triggered"` | Nothing: guardian sends no webhooks |
| `GET integrations/logs/error_summary/` | Zeros | `GET integrations/logs/?level=error` and read `count` |
| `POST integrations/notifications/{id}/test_notification/`, `send_notification/` | `"Test notification sent"`, `"Notification sent"` | Nothing: guardian delivers nothing through a channel |

### An integration has no stored credential

Three fields took secrets, kept them in guardian's database as plain text and
never returned them. Nothing used them, for the reasons above, so they were
removed with the values that were stored
([issue #728](https://github.com/fabriziosalmi/wildbox/issues/728)):

| Resource | Removed field | It held |
| --- | --- | --- |
| External systems | `auth_config` | API keys, bearer tokens, basic-auth passwords |
| Webhook endpoints | `secret_token` | The secret of a signature check nothing performs |
| Notification channels | `config` | Slack and Teams webhook URLs, SMTP passwords, push tokens |

A `POST`, `PUT` or `PATCH` that sends a value in one of them answers `400` on
that field and stores nothing:

```json
{
  "auth_config": [
    "guardian does not store the credentials of an external system: it contacts none, so nothing would use them. Leave this field out."
  ]
}
```

An empty value (`""`, `null`, `{}`, `[]`) is ignored. `auth_type` and
`verify_signature` stay: they say how the system authenticates and what the team
wants checked, which are not secrets. Do not put a credential in a free-form
field instead (`metadata`, `tags`, `description`, `field_mappings`,
`sync_filters`, a webhook's `filters`): those are stored as sent and returned to
every member of the team.

---

## Reports and alerts

Prefix: `reports/`.

| Resource | Path | Notes |
| --- | --- | --- |
| Report templates | `reports/templates/` | Standard routes |
| Report schedules | `reports/schedules/` | Standard routes |
| Reports | `reports/reports/` | Standard routes |
| Dashboards | `reports/dashboards/` | Standard routes. A caller sees the team's dashboards that are public in the team (`is_public`, `false` unless set), their own, and those shared with them; any other answers `404`, for `owner` and `admin` too |
| Widgets | `reports/widgets/` | Standard routes |
| Report metrics | `reports/metrics/` | Read-only (list and retrieve) |
| Alert rules | `reports/alerts/` | Standard routes |

Custom actions:

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `reports/templates/{id}/generate/` | Creates a report and queues its generation. Optional `parameters`, `filters`, `format`. Returns `202` with the report record |
| `GET` | `reports/templates/{id}/reports/` | Reports generated from the template |
| `GET` | `reports/templates/{id}/metrics/` | Metrics of the template |
| `POST` | `reports/schedules/{id}/run_now/` | Generates the scheduled report now. Returns `202` with the report record |
| `GET` | `reports/schedules/due/` | Active schedules whose next run is due |
| `GET` | `reports/reports/{id}/download/` | Downloads a completed report file; `400` while the report is not `completed` |
| `GET` | `reports/reports/recent/` | Recent reports |
| `GET` | `reports/reports/failed/` | Failed reports |
| `GET` | `reports/dashboards/{id}/data/` | Dashboard data |
| `POST` | `reports/dashboards/{id}/share/` | Shares the dashboard with users |
| `GET` | `reports/widgets/{id}/data/` | Widget data |
| `POST` | `reports/widgets/{id}/test/` | Tests the widget configuration |
| `GET` | `reports/metrics/summary/` | Reporting metrics summary |
| `POST` | `reports/alerts/{id}/test/` | Evaluates the rule now and returns `rule_triggered`, `current_value`, `threshold_value`, `test_time` |
| `GET` | `reports/alerts/{id}/notifications/` | Notifications of the rule, newest first (paginated). Each has `recipients` (who it was addressed to: the rule's own, or the team's owners and admins), `delivered` and, when it was not delivered, `failure_reason` |
| `POST` | `reports/alerts/check_all/` | Queues a check of all active rules; returns `task_id` |

Only some reports can be produced (`SUPPORTED_REPORT_TYPES` and
`SUPPORTED_REPORT_FORMATS` in `apps/reporting/models.py`):

- Report types: `vulnerability_summary`, `asset_inventory`, `compliance_status`,
  `executive_dashboard`.
- Formats: `json`, `html`.

Generating any other type or format creates a report that the worker marks as
failed, with the reason. A template's `default_format` is `pdf` unless set, so pass
`format` explicitly. Creating or updating a report schedule with an unsupported
template type or format answers `400` with the reason in `template` or `format`.

A generated report is processed by a worker. Poll `reports/reports/{id}/` until its
`status` is `completed`, then download it. A report record has `file_size` and
`file_hash` (SHA-256) once its file is written, and no path: where guardian keeps
the file is not part of the API (the `file_path` field was removed in #724). A
report whose `status` is `failed` has the reason in `error_message`.

```bash
curl -s --cacert "$CA" -X POST "$BASE/reports/templates/<template-id>/generate/" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"format": "html"}'

curl -s --cacert "$CA" -OJ "$BASE/reports/reports/<report-id>/download/" \
  -H "Authorization: Bearer $TOKEN"
```

---

## Task status

Four actions answer with a `task_id`: `assets/assets/{id}/scan/`,
`assets/assets/discover/`, `assets/discovery-rules/{id}/execute/` and
`reports/alerts/check_all/`. (Report generation answers the report record
instead: poll `reports/reports/{id}/`.) Read the task's state with:

```bash
curl -s --cacert "$CA" "$BASE/tasks/<task-id>/" \
  -H "Authorization: Bearer $TOKEN"
```

```json
{
  "task_id": "3f2b8c1e-7d4a-4e09-9a51-0c6d2f8e4b17",
  "state": "SUCCESS",
  "ready": true,
  "successful": true,
  "queue": "scanning"
}
```

An ID that the caller's team did not dispatch, whether another team's or
unknown, answers `404`. Otherwise `state` is `PENDING`, `STARTED`, `SUCCESS`, `FAILURE` or
`RETRY`; `successful` is `null` until `ready` is `true`; `queue` is `null` until a
worker has taken the task. The task's result and traceback are never returned.

This is guardian's own task route, `/api/v1/guardian/tasks/<uuid>/`. The gateway path
`/api/v1/tasks/...` (without `guardian`) belongs to the tools service and does not
know guardian's tasks.

---

## Health check

Guardian's health check is `GET /health/`, with the trailing slash, on guardian's
own port (bound to `127.0.0.1:8013` in `docker-compose.yml`). It is not under
`/api/v1/`, so the gateway does not route it. It needs no authentication and
returns `200` with `"status": "healthy"`, or `503` with `"status": "unhealthy"`,
plus a `checks` object with the status of the database and Redis. It is not rate
limited.

---

## Rate limits

Two limits apply to guardian requests:

- **Gateway, per team.** The gateway allows `RATE_LIMIT_PER_HOUR` requests per
  hour per team, 10000 unless the deployment sets it, enforced in fixed 60-second
  windows of one sixtieth of that figure, rounded down and at least 1 (166 with
  the default).
  `X-RateLimit-Limit`, `X-RateLimit-Remaining` and `X-RateLimit-Reset` describe
  the current minute window, and `X-RateLimit-Policy` is the hourly figure, such
  as `10000;w=3600`. The gateway validates the variable at startup and does not
  start when it is not a whole number from 1 to 1,000,000,000.
- **Guardian, per user.** Guardian allows each user `GUARDIAN_RATE_LIMIT_USER`
  requests, 1000 per hour unless the deployment sets it, counted on the user the
  gateway authenticated (`X-Wildbox-User-ID`), not on an address
  (`apps/core/throttling.py`). The value is `<count>/<period>`
  with a period of `second`, `minute`, `hour` or `day`, for example `20/minute`, or
  `off` to leave only the gateway's limit. Guardian checks it at startup and does
  not start with any other value. One member cannot use up guardian for the rest
  of the team this way; the team as a whole is held by the gateway's limit.

Both answer `429 Too Many Requests` when exceeded. Guardian's throttle body is
`{"detail": "Request was throttled. Expected available in N seconds."}`, with the
same number of seconds in `Retry-After`.

Guardian has no limit for anonymous callers, because it has no anonymous callers:
a request under `/api/` that did not come through the gateway is refused (see
[Gateway only](#gateway-only)). Before #645 it carried one, 100 requests per hour
per address, whose only reachable route was the [health check](#health-check); and
the variable it read for both rates, `API_RATE_LIMIT`, was not passed to the
container by `docker-compose.yml`.

---

## Errors

Guardian answers errors in Django REST Framework's format:

| Status | Meaning | Body |
| --- | --- | --- |
| `400` | Validation failed, or an unsupported action | Field errors (`{"name": ["This field is required."]}`), `{"detail": "..."}` or `{"error": "..."}` |
| `401` | No valid credential (answered by the gateway) | Gateway JSON |
| `403` | Role or API key scope does not allow the request; or a request that did not come through the gateway | `{"detail": "..."}`, the gateway's `insufficient_scope` body, or `{"code": "GATEWAY_AUTH_REQUIRED", ...}` |
| `404` | Unknown ID or route | `{"detail": "..."}` |
| `409` | The request conflicts with what is stored | `{"detail": "...", "code": "WORKFLOW_EXISTS"}` |
| `501` | The record exists and guardian cannot do this with it | `{"detail": "...", "code": "DISCOVERY_TYPE_NOT_IMPLEMENTED"}` |
| `429` | Rate limit exceeded | See [Rate limits](#rate-limits) |

---

## Related Documentation

- [Identity Service API](../identity/endpoints.md) - Sign-in and API keys
- [Authentication guide](../../guides/authentication.md) - Tokens and API keys through the gateway
- [Service ports](../../guides/ports.md) - Which ports each service binds
- [Security Policy](../../security/policy.md) - Authentication and authorization requirements
