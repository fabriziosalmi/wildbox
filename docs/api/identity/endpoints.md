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
| PATCH | `/api/v1/users/me` | Update the authenticated user (fastapi-users); an email change needs `current_password`, a password is refused |
| PATCH | `/api/v1/admin/me/profile` | Change the email; body `email`, `current_password` |
| PUT | `/api/v1/admin/me` | Same as `PATCH /api/v1/admin/me/profile` |
| PUT | `/api/v1/admin/me/password` | Change password; same body as below |
| POST | `/api/v1/admin/me/change-password` | Change password; body `current_password`, `new_password`; answers a new `access_token` and ends the account's other sessions |
| DELETE | `/api/v1/admin/me/account` | Deactivate own account; body `password`, `confirm_deletion` |
| GET | `/api/v1/admin/me/activity` | Own recent activity; `team_memberships` oldest first, the first being the team the session works in |

Despite the `/admin` prefix, the `/admin/me/...` routes act on the caller's own
account and need only a valid token.

A wrong `current_password` (or `password` on account deletion) counts
towards the login lockout, and a locked account answers 429 there as at
login.

Every route that sets a password hashes it with Argon2id through
fastapi-users' `PasswordHelper`, the same helper login verifies with; bcrypt
hashes from older releases still verify.

### Password Policy

Every route that sets a password applies the same rule
(`UserManager.validate_password()`): 12 to 128 characters, not containing
the account's email address or the part before the `@` (when it has at
least 4 characters), and not one of the 10,000 most common passwords of
that length (a list vendored in identity). There are no composition rules.
The [authentication guide](../../guides/authentication.md#password-policy)
explains the choices.

| Route | Refusal |
| --- | --- |
| `POST /api/v1/auth/register` | 400, `error.details.code` `REGISTER_INVALID_PASSWORD` |
| `POST /api/v1/auth/reset-password` | 400, `error.details.code` `RESET_PASSWORD_INVALID_PASSWORD` |
| `PATCH /api/v1/users/{id}` (superuser) | 400, `error.details.code` `UPDATE_USER_INVALID_PASSWORD` |
| `POST /api/v1/admin/me/change-password`, `PUT /api/v1/admin/me/password` | 400; 422 for fewer than 12 or more than 128 characters |
| `POST /api/v1/admin/teams/{team_id}/members` | 400; 422 for fewer than 12 or more than 128 characters |

`error.message` carries the reason, for example:

```json
{"error": {"code": 400, "message": "The password must be at least 12 characters long.",
  "type": "HTTPException", "request_id": "...",
  "details": {"code": "REGISTER_INVALID_PASSWORD",
              "reason": "The password must be at least 12 characters long."}}}
```

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
| GET | `/api/v1/api-keys` | List the caller's own keys |
| GET | `/api/v1/api-keys/{key_prefix}` | Show one of the caller's keys |
| DELETE | `/api/v1/api-keys/{key_prefix}` | Revoke one of the caller's keys |

These act in the caller's primary team and on the keys the caller created:
another member's key answers 404, as a key that does not exist does. They
used to match any key of the team, so a member could revoke a teammate's or
the owner's key (#664).

All the keys of a team, whoever created them:

| Method | Path | Role in the team |
| --- | --- | --- |
| POST | `/api/v1/teams/{team_id}/api-keys` | `admin` or `owner` |
| GET | `/api/v1/teams/{team_id}/api-keys` | any member |
| GET | `/api/v1/teams/{team_id}/api-keys/{key_prefix}` | any member |
| DELETE | `/api/v1/teams/{team_id}/api-keys/{key_prefix}` | `admin` or `owner` |

### Revocation Takes Effect at Once

A revoked key is refused by the gateway on the next request. Before it marks
the key inactive, identity has the gateway refuse it, by the key's id, and
the gateway confirms; if it does not, the key stays active and the DELETE
answers **503**, to be repeated. The same holds, with the same 503, for every
other change that disables keys: deactivating or deleting an account (all its
keys and sessions), deleting one's own account, and removing a member from a
team (the member's keys for that team). A key's `expires_at` is honored even
when the gateway has a decision for the key in its cache. See
[Revoking an API key](../../guides/authentication.md#revoking-an-api-key).

`/internal/authorize` reports, for an API key, `api_key_id` (what the gateway
revokes the key by) and `credential_expires_at` (the key's expiry in epoch
seconds, or null); for a session token, `credential_expires_at` is the
token's `exp`.

---

## Teams

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/v1/admin/teams/{team_id}/members` | List members |
| POST | `/api/v1/admin/teams/{team_id}/members` | Create an account in the team; body `email`, `password`, `role` |
| PUT | `/api/v1/admin/teams/{team_id}` | Update a team |
| DELETE | `/api/v1/admin/teams/{team_id}/members/{user_id}` | Remove a member |

Listing members is open to any member of the team. Creating, updating and
removing need the `owner` or `admin` role in that team, or a superuser.

### Create a Member

`POST /api/v1/admin/teams/{team_id}/members` creates a **new** account whose
only membership is this team; it gets no team of its own, so its sessions
work in this team. There is no adding of an existing account, and no email
is sent: the administrator gives the new member the initial password.

```json
{"email": "new.member@example.com", "password": "an initial password", "role": "member"}
```

- `password`: must meet the [password policy](#password-policy). The
  account is created with `must_change_password: true`.
- `role`: `member` (the default) or `admin`, strictly below the caller's
  own role: an owner (or a superuser) creates admins and members, an admin
  creates members. `owner` is never accepted.

| Status | When |
| --- | --- |
| 201 | Created; the body is the new membership, as in the member list |
| 403 | The caller is not an owner or admin of the team, or the role is not one it may give |
| 404 | A superuser named a team that does not exist |
| 400 | The password does not meet the policy; `error.message` says why |
| 409 | The email is already registered (in any letter case) |
| 422 | Invalid email, unknown role, or a password under 12 or over 128 characters |

The creation is logged (`audit: team_member_created`) with the caller, the
new account, the team and the role, never the password.

### Accounts That Must Change Their Password

While `must_change_password` is true (`GET /api/v1/users/me` reports it),
the account's sessions can only read the account (`GET /api/v1/users/me`),
change the password (`POST /api/v1/admin/me/change-password`, or `PUT
/api/v1/admin/me/password`) and log out. Every other identity route answers
403 with the message `PASSWORD_CHANGE_REQUIRED`, and the gateway answers
403 `{"error": "PASSWORD_CHANGE_REQUIRED"}` for every other service, because
`/internal/authorize` reports `password_change_required: true`. Changing the
password clears the flag and returns a new token, as for any password
change.

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
| GET | `/api/v1/admin/metrics` | User, team and active API-key counts |

`/api/v1/admin/metrics` used to accept the `X-Gateway-Secret` header in
place of a user, and the gateway sent that header on every request it passed
to identity, so anyone could read the counts (#664). It now takes a
superuser's bearer token like the other routes here, and the gateway sends
its secret only on requests it authenticated itself.

fastapi-users also registers `GET`, `PATCH` and `DELETE` on
`/api/v1/users/{id}` for superusers.

Deactivating an account (through either route) or deleting it ends its API
keys and sessions at the gateway before the change is committed; when the
gateway does not confirm, nothing changes and the answer is 503.

---

## Service Routes

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/health` | Health check |
| GET | `/` | Service information |
| POST | `/internal/authorize` | Token and API-key validation for the gateway; requires `X-Gateway-Secret` and is not routed by the gateway |

`/internal/authorize` is the only identity route that accepts
`X-Gateway-Secret`. The gateway calls it on its own behalf, with the secret
from its environment; no gateway location maps a client path to `/internal`.

---

## Related Documentation

- [Authentication and sessions](../../guides/authentication.md)
- [Credentials](../../guides/credentials.md)
- [Quick Start](../../guides/quickstart.md)
- [Gateway routes](https://www.wildbox.io/docs.html#gateway-routes)
