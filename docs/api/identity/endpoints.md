# Identity & Authentication Service API

The identity service (`open-security-identity`, FastAPI with fastapi-users)
owns users, JWT login, API keys and teams, and answers the gateway's
authorization checks.

**Gateway path**: `https://<host>/api/v1/identity/...` (proxied to the service's `/api/v1/...`); login at `https://<host>/auth/jwt/login`  
**Local port**: listed in [Service ports](../../guides/ports.md)  
**Authentication**: JWT bearer token; identity validates it itself on its routes

This page lists the routes registered in
[`open-security-identity/app/main.py`](https://github.com/fabriziosalmi/wildbox/blob/main/open-security-identity/app/main.py)
and the modules it includes. For request and response schemas, a running
service publishes its OpenAPI document at `/openapi.json` and Swagger UI at
`/docs` (on its local port, not through the gateway).

---

## Authentication

### Log In

`POST /api/v1/auth/jwt/login` (gateway: `POST /auth/jwt/login`)

Form-encoded body, as defined by OAuth2 password flow: `username` (the email
address) and `password`. Returns:

```json
{
  "access_token": "<JWT>",
  "token_type": "bearer"
}
```

Wrong credentials return 400. The token lifetime is
`JWT_ACCESS_TOKEN_EXPIRE_MINUTES` (30 minutes by default). There is no refresh
endpoint; log in again when the token expires.

```bash
TOKEN=$(curl -s --cacert open-security-gateway/ssl/wildbox.crt \
  -X POST https://localhost/auth/jwt/login \
  --data-urlencode "username=$ADMIN_EMAIL" \
  --data-urlencode "password=$ADMIN_PASSWORD" | jq -r .access_token)
```

The [Quick Start](../../guides/quickstart.md#5-log-in-and-call-the-api) shows
where `ADMIN_EMAIL` and `ADMIN_PASSWORD` come from.

### Log Out

`POST /api/v1/auth/logout` (gateway: `POST /auth/logout`) with
`Authorization: Bearer <token>`. Adds the token's `jti` to a blacklist until
the token would have expired, and asks the gateway to drop it from its
authorization cache. Returns 200 whether or not the token was already revoked;
401 without a bearer token.

### Other Authentication Routes

All under `/api/v1/auth` (fastapi-users):

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/register` | Create an account (gateway: `/auth/register`) |
| POST | `/forgot-password` | Request a password reset token |
| POST | `/reset-password` | Reset a password with that token |
| POST | `/request-verify-token` | Request an email verification token |
| POST | `/verify` | Verify an email address |

---

## Current User

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/v1/users/me` | The authenticated user |
| PATCH | `/api/v1/users/me` | Update the authenticated user (fastapi-users) |
| PATCH | `/api/v1/admin/me/profile` | Update profile fields |
| PUT | `/api/v1/admin/me` | Update the authenticated user |
| PUT | `/api/v1/admin/me/password` | Change password |
| POST | `/api/v1/admin/me/change-password` | Change password; body `current_password`, `new_password` |
| DELETE | `/api/v1/admin/me/account` | Delete own account |
| GET | `/api/v1/admin/me/activity` | Own recent activity |

Despite the `/admin` prefix, the `/admin/me/...` routes act on the caller's own
account and need only a valid token.

```bash
curl -s --cacert open-security-gateway/ssl/wildbox.crt \
  -H "Authorization: Bearer $TOKEN" https://localhost/api/v1/identity/users/me
```

---

## API Keys

Personal API keys, sent to the gateway as `X-API-Key: <key>`. The secret is
returned once, when the key is created.

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/api/v1/api-keys` | Create a key for the caller |
| GET | `/api/v1/api-keys` | List the caller's keys |
| GET | `/api/v1/api-keys/{key_prefix}` | Show one key |
| DELETE | `/api/v1/api-keys/{key_prefix}` | Revoke a key |

Team keys, which require the `admin` or `owner` role in the team:

| Method | Path |
| --- | --- |
| POST | `/api/v1/teams/{team_id}/api-keys` |
| GET | `/api/v1/teams/{team_id}/api-keys` |
| GET | `/api/v1/teams/{team_id}/api-keys/{key_prefix}` |
| DELETE | `/api/v1/teams/{team_id}/api-keys/{key_prefix}` |

---

## Teams

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/v1/admin/teams/{team_id}/members` | List members |
| POST | `/api/v1/admin/teams/{team_id}/invite` | Invite a member |
| PUT | `/api/v1/admin/teams/{team_id}` | Update a team |
| DELETE | `/api/v1/admin/teams/{team_id}/members/{user_id}` | Remove a member |

---

## Platform Administration

These require a superuser (`is_superuser`); being the owner or admin of a team
is not enough.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/v1/admin/users` | List users |
| GET | `/api/v1/admin/users/{user_id}` | One user with teams |
| GET | `/api/v1/admin/users/{user_id}/can-delete` | Check whether a user can be deleted |
| PATCH | `/api/v1/admin/users/{user_id}/status` | Activate or deactivate |
| PATCH | `/api/v1/admin/users/{user_id}/superuser` | Grant or revoke superuser |
| PATCH | `/api/v1/admin/users/{user_id}/role` | Promote or demote a superuser |
| DELETE | `/api/v1/admin/users/{user_id}` | Delete a user |
| GET | `/api/v1/analytics/admin/system-stats` | Platform statistics |
| GET | `/api/v1/analytics/admin/user-activity` | User activity |
| GET | `/api/v1/analytics/admin/usage-summary` | Usage summary |

fastapi-users also registers `GET`, `PATCH` and `DELETE` on
`/api/v1/users/{id}` for superusers.

---

## Service Routes

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/health` | Health check |
| GET | `/` | Service information |
| GET | `/api/v1/admin/metrics` | User, team and API-key counts; requires `X-Gateway-Secret`, not a user token |
| POST | `/internal/authorize` | Token and API-key validation for the gateway; requires `X-Gateway-Secret` and is not routed by the gateway |

---

## Related Documentation

- [Credentials and authentication](../../guides/credentials.md)
- [Quick Start](../../guides/quickstart.md)
- [Gateway routes](https://www.wildbox.io/docs.html#gateway-routes)
