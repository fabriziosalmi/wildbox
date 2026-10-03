# Identity & Authentication Service API

The identity service (`open-security-identity`, FastAPI with fastapi-users)
owns users, JWT (JSON Web Token) login, API keys and teams, and answers the gateway's
authorization checks.

**Gateway path**: `https://<host>/api/v1/identity/...` (proxied to the service's `/api/v1/...`); login at `https://<host>/auth/jwt/login`  
**Local port**: listed in [Service ports](../../guides/ports.md)  
**Authentication**: JWT bearer token; identity validates it itself on its routes

This page lists the routes registered in
[`open-security-identity/app/main.py`](https://github.com/fabriziosalmi/wildbox/blob/main/open-security-identity/app/main.py)
and the modules it includes. For request and response schemas, the service
publishes its OpenAPI document at `/openapi.json`, Swagger UI at `/docs` and
ReDoc at `/redoc` on its local port (not through the gateway), only when
`ENVIRONMENT` is not `production`. The `.env` written by
`make generate-secrets` sets `ENVIRONMENT=production`, so those three paths
answer 404 in the default stack.

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

Wrong credentials return 400. After 5 failed logins for the same email the
account is locked for 15 minutes: every login, even with the right password,
returns 429 with `Retry-After: 900`. Tokens are HS256 JWTs valid for 30
minutes, with no refresh endpoint. Lifetime, claims, revocation, the lockout
and password hashing are described once, in the
[Authentication and sessions guide](../../guides/authentication.md).

```bash
TOKEN=$(curl -s --cacert open-security-gateway/ssl/wildbox.crt \
  -X POST https://localhost/auth/jwt/login \
  --data-urlencode "username=$ADMIN_EMAIL" \
  --data-urlencode "password=$ADMIN_PASSWORD" | jq -r .access_token)
```

The [Quick Start](../../guides/quickstart.md#5-log-in-and-call-the-api) shows
where `ADMIN_EMAIL` and `ADMIN_PASSWORD` come from.

### Log Out

`POST /api/v1/auth/logout` (gateway: `POST /auth/logout`), or the
fastapi-users route `POST /api/v1/auth/jwt/logout` (gateway:
`POST /auth/jwt/logout`), with
`Authorization: Bearer <token>`. Has the gateway refuse the token's `jti`
and adds it to a blacklist until the token would have expired. Returns 200
whether or not the token was already revoked; 401 without a bearer token;
400 for a token without a `jti` (issued before the release that added it),
which expires on its own; 503 when the gateway did not confirm the
revocation or the blacklist could not be written, in which case the token is
still valid and the logout can be repeated.

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
| PUT | `/api/v1/admin/me/password` | Change password; same body as below |
| POST | `/api/v1/admin/me/change-password` | Change password; body `current_password`, `new_password` |
| DELETE | `/api/v1/admin/me/account` | Deactivate own account; body `password`, `confirm_deletion` |
| GET | `/api/v1/admin/me/activity` | Own recent activity |

Despite the `/admin` prefix, the `/admin/me/...` routes act on the caller's own
account and need only a valid token.

Every route that sets a password hashes it with Argon2id through
fastapi-users' `PasswordHelper`, the same helper login verifies with; bcrypt
hashes from older releases still verify.

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

- [Authentication and sessions](../../guides/authentication.md)
- [Credentials](../../guides/credentials.md)
- [Quick Start](../../guides/quickstart.md)
- [Gateway routes](https://www.wildbox.io/docs.html#gateway-routes)
