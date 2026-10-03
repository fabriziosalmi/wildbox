# Gateway Authentication Pattern: Developer Guide

> **Example values are fictitious.** Keys, tokens, IDs and host names below
> are placeholders; `example.com` is reserved for documentation by RFC 2606.
> Never paste a real credential into documentation.

## Overview

The gateway (`open-security-gateway`, OpenResty) is the single entry point.
It authenticates the caller with identity, then forwards the request to the
backend service with the caller's identity in `X-Wildbox-*` headers and a
proof of origin in `X-Gateway-Secret`. The backend checks the proof of origin
and trusts the headers; it never sees the caller's credential.

```text
Client --(JWT or API key)--> Gateway --(POST /internal/authorize)--> Identity
                               |
                               +--(X-Wildbox-* + X-Gateway-Secret)--> Backend
```

## What the gateway does

On every authenticated `/api/v1/` route except identity's own, the gateway runs the
shared handler (`authenticate()` in
`open-security-gateway/nginx/lua/auth_handler.lua`):

1. It reads the credential: `Authorization: Bearer <token>` first, otherwise
   `X-API-Key: <key>`. A cookie alone is not a credential. Without either it
   answers `401` with `{"error":"authentication_required",...}`.
2. It asks identity (`POST /internal/authorize`, with `X-Gateway-Secret`) to
   validate the credential, and caches the answer. A credential identity
   refuses gets `401` (`invalid_token`); identity unreachable gets `503`.
3. It checks revocation markers, password changes, API-key revocation and
   team removal, and the API key's scopes, and applies the per-team limit of
   `RATE_LIMIT_PER_HOUR` requests per hour (10000 by default), enforced in
   60-second windows of one sixtieth of that figure (166 with the default).
   The gateway validates `RATE_LIMIT_PER_HOUR` at startup and does not start
   when it is not a whole number from 1 to 1,000,000,000.
4. It removes `Authorization`, `X-API-Key` and any client-supplied
   `X-Wildbox-User-ID`, `X-Wildbox-Team-ID` and `X-Wildbox-Role`
   (`utils.clean_request_headers()`), then stores the validated identity in
   the nginx variables `$wildbox_user_id`, `$wildbox_team_id` and
   `$wildbox_role`.

The shared proxy settings, `open-security-gateway/nginx/includes/proxy_params.conf`,
which every proxied route includes, then send:

```nginx
proxy_set_header X-Wildbox-User-ID $wildbox_user_id;
proxy_set_header X-Wildbox-Team-ID $wildbox_team_id;
proxy_set_header X-Wildbox-Role $wildbox_role;
proxy_set_header X-Gateway-Secret $gateway_secret;
proxy_set_header X-Request-ID $request_id;
proxy_set_header Authorization "";
```

`$gateway_secret` is set in the server block from the gateway's
`GATEWAY_INTERNAL_SECRET` environment variable, so a client cannot supply it.
The server block initializes the three `$wildbox_*` variables to empty
strings, and nginx does not send a header whose value is empty.

### Routes that differ

- **Identity** (`/api/v1/identity/`, `/auth/`): identity is the
  authentication authority and validates the bearer token itself, so these
  routes do not run the shared handler and pass `Authorization` through.
- **Guardian** (`/api/v1/guardian/`): uses the shared handler, but guardian is
  a Django service with its own middleware
  (`open-security-guardian/apps/core/gateway_middleware.py`) rather than the
  FastAPI dependency below. Like the FastAPI services, it accepts gateway
  headers only and answers a direct request with `403`
  `GATEWAY_AUTH_REQUIRED`; it has no API keys of its own (#633).

## Identity headers

| Header | Content |
| --- | --- |
| `X-Wildbox-User-ID` | The caller's user ID (UUID) |
| `X-Wildbox-Team-ID` | The caller's team ID (UUID) |
| `X-Wildbox-Role` | The caller's role in the team: `owner`, `admin`, `member` or `viewer` |
| `X-Gateway-Secret` | The shared `GATEWAY_INTERNAL_SECRET`: the proof that the request came from the gateway |

There is no plan or subscription header.

## Using it in a FastAPI service

### Install the shared package

The shared code is the `open-security-shared` directory, installed as the
Python package `open_security_shared`. Services build with it as an extra
build context; in `docker-compose.yml`:

```yaml
build:
  context: ./open-security-myservice
  dockerfile: Dockerfile
  additional_contexts:
    shared: ./open-security-shared
```

and in the service's `Dockerfile`:

```dockerfile
COPY --from=shared . /tmp/open-security-shared
RUN pip install --no-deps /tmp/open-security-shared
```

`--no-deps` because the service's own `requirements.txt` already provides the
package's dependencies (FastAPI, Pydantic and the others listed in
`open-security-shared/pyproject.toml`).

### Authenticate a route

`open_security_shared.gateway_auth` provides `GatewayUser`,
`get_user_from_gateway_headers` and `require_role`. Most services re-export
them from their own `app/auth.py`, as the data and agents services do:

```python
# open-security-myservice/app/auth.py
from open_security_shared.gateway_auth import (
    GatewayUser,
    get_user_from_gateway_headers,
    require_role,
)

get_current_user = get_user_from_gateway_headers

__all__ = ["GatewayUser", "get_current_user", "require_role"]
```

```python
# open-security-myservice/app/main.py
from fastapi import Depends, FastAPI

from app.auth import GatewayUser, get_current_user, require_role

app = FastAPI()


@app.get("/api/v1/items")
async def list_items(user: GatewayUser = Depends(get_current_user)):
    # user.user_id and user.team_id are UUIDs; user.role is a string.
    return {"team_id": str(user.team_id)}


@app.delete("/api/v1/items/{item_id}")
async def delete_item(
    item_id: str,
    user: GatewayUser = Depends(get_current_user),
    _: None = Depends(require_role("owner", "admin")),
):
    return {"deleted": item_id}
```

Scope every query by `user.team_id`: the gateway authenticates the caller,
the service decides what that caller may see.

### What the dependency checks

`get_user_from_gateway_headers` (`open-security-shared/gateway_auth.py`), in
this order:

| Condition | Status | `code` |
| --- | --- | --- |
| The service has no `GATEWAY_INTERNAL_SECRET` | 503 | `GATEWAY_SECRET_NOT_CONFIGURED` |
| `X-Wildbox-User-ID` or `X-Wildbox-Team-ID` missing | 403 | `GATEWAY_AUTH_REQUIRED` |
| `X-Gateway-Secret` missing or different (constant-time comparison) | 403 | `GATEWAY_SECRET_REQUIRED` |
| User or team ID not a UUID4 | 400 | `INVALID_GATEWAY_HEADERS` |
| Role not one of `owner`, `admin`, `member`, `viewer` (missing means `member`) | 400 | `INVALID_GATEWAY_HEADERS` |

`require_role(...)` answers `403` with `code` `INSUFFICIENT_ROLE` when the
caller's role is not in the list.

The tools service wraps the dependency (`open-security-tools/app/auth.py`):
a request without the identity headers gets `401` there instead of `403`.

Services that install the shared error handlers
(`open_security_shared.errors.install_error_handlers`) return these errors in
the canonical body, `{"error": {"code", "message", "type", "request_id"}}`.

### Calls between services

A service that calls another one on behalf of a user forwards that user's
identity: the same three `X-Wildbox-*` headers and `X-Gateway-Secret`. There
is no service-wide key. The agents service does this for its tool calls
(`open-security-agents/app/tools/wildbox_client.py`, `_request_headers()`),
and refuses to make a call when it has no complete caller identity.

## Testing

Through the gateway, which serves HTTPS with the certificate in
`open-security-gateway/ssl/`:

```bash
CA=open-security-gateway/ssl/wildbox.crt

# Valid API key: 200 with the tool's result
curl --cacert "$CA" -X POST https://<host>/api/v1/tools/whois_lookup \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# Invalid API key: 401 from the gateway
curl --cacert "$CA" -X POST https://<host>/api/v1/tools/whois_lookup \
  -H "X-API-Key: invalid-key" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

Directly on a backend port (bound to `127.0.0.1` on the host), without the
gateway's headers, the request is refused:

```bash
# 401 from the tools service
curl -X POST http://127.0.0.1:8000/api/tools/whois_lookup \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

## Troubleshooting

**The service logs "Missing gateway authentication headers".** The request
reached the service without `X-Wildbox-User-ID` or `X-Wildbox-Team-ID`. Check
that it went through the gateway, and that the gateway route calls
`auth_handler.authenticate()` in an `access_by_lua_block`. Loading the module
with `access_by_lua_file` does not call it, and that route then runs without
authentication.

**The service answers `GATEWAY_SECRET_REQUIRED`.** The gateway and the
service hold different `GATEWAY_INTERNAL_SECRET` values, typically after a
rotation in which not every container was recreated. See
[Secrets rotation](SECURITY_SECRETS_ROTATION.md).

**`ModuleNotFoundError: open_security_shared`.** The image was built without
the `shared` build context or without the `pip install` step above.

## Best practices

1. Never publish a backend port beyond `127.0.0.1`; the gateway is the entry
   point.
2. Do not read credentials in a backend service; use the identity headers.
3. Fail closed: a missing or invalid header is a refusal, never a default
   user.
4. Log `user.user_id` and `user.team_id` for audit trails.

The reference implementation is `open-security-shared/gateway_auth.py`.
