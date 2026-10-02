# Authentication and Sessions

How a client logs in, how long a session lasts, how it ends, and what happens
after repeated failed logins. Everything on this page comes from
`open-security-identity/app/` (`config.py`, `user_manager.py`, `logout.py`,
`token_blacklist.py`, `gateway_cache.py`) and the gateway configuration in
`open-security-gateway/nginx/`. Where secrets come from is in the
[Credentials guide](credentials.md).

---

## Credentials the Gateway Accepts

Clients authenticate at the gateway (`https://<host>/`), with either:

- a **JWT (JSON Web Token) bearer token**, `Authorization: Bearer <token>`,
  obtained by logging in; or
- an **API key**, `X-API-Key: <key>`. Create one while logged in with
  `POST /api/v1/identity/api-keys`; the secret is shown once, in the response.

The gateway asks identity to validate each credential (`POST
/internal/authorize`, which only the gateway can call) and caches the answer;
see [When identity is unreachable](#when-identity-is-unreachable).

---

## Logging In

`POST /auth/jwt/login` through the gateway, form-encoded, with the email
address as `username`:

```bash
CA=open-security-gateway/ssl/wildbox.crt
TOKEN=$(curl -s --cacert "$CA" -X POST https://localhost/auth/jwt/login \
  --data-urlencode "username=$ADMIN_EMAIL" \
  --data-urlencode "password=$ADMIN_PASSWORD" | jq -r .access_token)
```

The [Quick Start](quickstart.md#5-log-in-and-call-the-api) shows where
`ADMIN_EMAIL` and `ADMIN_PASSWORD` come from.

| Response | Meaning |
| --- | --- |
| 200 with `access_token` and `token_type: bearer` | Logged in |
| 400 | Wrong email or password |
| 429 with a `Retry-After` header | The account is locked after repeated failures; see [Failed-login lockout](#failed-login-lockout) |
| 429 without `Retry-After` | The gateway's rate limit on `/auth/jwt/`: 5 requests per second per client address, burst 3 |

---

## Tokens

| Property | Value |
| --- | --- |
| Signing | HS256 with `JWT_SECRET_KEY` |
| Claims | `sub` (user ID), `aud` (`fastapi-users:auth`), `exp`, `iat`, and a random `jti` |
| Lifetime | 30 minutes (`jwt_access_token_expire_minutes`). `docker-compose.yml` does not pass `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` to the identity container, so setting it in `.env` alone has no effect |
| Refresh | None. When a token expires, log in again |

Every login returns a different token, even two in the same second, because
each carries its own `jti`.

---

## Logging Out and Revocation

Either route revokes the token it is called with:

```bash
curl -s --cacert "$CA" -X POST -H "Authorization: Bearer $TOKEN" \
  https://localhost/auth/logout
```

`POST /auth/jwt/logout` does the same; it is the route the dashboard's logout
calls. Both answer 200 whether or not the token was already revoked, and 401
without a bearer token.

What revocation does:

1. identity writes the token's `jti` to a blacklist in Redis, kept until the
   token would have expired anyway;
2. identity's own routes refuse a blacklisted token from then on;
3. identity asks the gateway to drop the token from its authorization cache,
   on the gateway's internal listener (port 8081, reachable only on the
   Compose network, not published to the host), so the gateway refuses it at
   once instead of after its cache entry expires.

Limits to know:

- Logout revokes **one token**, the one presented. There is no "log out
  everywhere", and changing a password does not revoke tokens issued before
  the change; they expire on their own within 30 minutes.
- Tokens issued before the upgrade that added the `jti` claim carry none.
  Logging out with one answers 400 ("Token carries no jti and cannot be
  revoked individually"); it expires within 30 minutes of being issued.
- If the gateway cache purge fails (identity logs it), the gateway can keep
  accepting the revoked token from its cache for up to `AUTH_CACHE_TTL`
  (300 seconds by default). identity itself refuses it immediately.
- The blacklist lives in Redis and is checked **fail-open**: if identity
  cannot reach Redis, it logs the error and treats tokens as not revoked.
  Keep Redis available; a revocation is only as reliable as Redis is.

Deactivating a user (`PATCH /api/v1/identity/admin/users/{user_id}/status`)
also clears the gateway's authorization cache, and the gateway refuses
inactive users' tokens and API keys from then on.

---

## Failed-Login Lockout

Password login is limited per account:

- Every failed login increments a counter keyed by the email address,
  trimmed and lower-cased. The counter expires 15 minutes after the first
  failure.
- Once 5 failures have been counted, the next login attempt locks the account
  for 15 minutes: every login answers 429 with `Retry-After: 900`, **even with
  the correct password**.
- A successful login before the limit clears the counter.
- An email that belongs to no account is counted and locked the same way, so
  the response does not reveal which addresses are registered.

The lockout applies to `POST /auth/jwt/login` only. API keys and tokens
already issued keep working. The limits are `max_failed_login_attempts` (5)
and `account_lockout_minutes` (15) in identity's settings; like the token
lifetime, Compose does not pass them to the container.

Because anyone who knows an email address can trigger the lock, an attacker can
keep an account locked out. To lift a lock early, delete its two keys from
Redis database 0 (replace the address, lower-cased):

```bash
docker compose exec \
  -e REDISCLI_AUTH="$(sed -n 's/^REDIS_PASSWORD=//p' .env)" wildbox-redis \
  redis-cli -n 0 DEL "login:lockout:user@example.com" "login:attempts:user@example.com"
```

Like the blacklist, the lockout check is fail-open: while Redis is unreachable,
logins are not counted or refused.

---

## Passwords

Passwords are hashed with Argon2id through fastapi-users' `PasswordHelper`.
Hashes written by older releases with bcrypt still verify.

A user changes their own password with either:

- `PATCH /api/v1/identity/users/me` with `{"password": "<new password>"}`; or
- `POST /api/v1/identity/admin/me/change-password` with `current_password`
  and `new_password` (or `PUT /api/v1/identity/admin/me/password`), which
  checks the current password first.

Deleting one's own account (`DELETE /api/v1/identity/admin/me/account`)
also requires the current password. The full list of routes is in the
[identity API reference](../api/identity/endpoints.md).

---

## When Identity Is Unreachable

The gateway calls identity with a 5-second timeout and caches each
authorization decision for `AUTH_CACHE_TTL` seconds (300 by default):

- a credential already in the cache keeps working during an identity outage,
  until its cache entry expires;
- a credential not in the cache gets 503;
- after 10 failed calls, each within 60 seconds of the previous one, the
  gateway stops calling identity for 60 seconds (circuit breaker) and answers
  503 at once, then tries again.

The nightly chaos suite (`tests/chaos/`) checks each of these behaviors
against a running stack.

---

## Related Pages

- [Credentials](credentials.md): generated secrets, the first administrator,
  rotation
- [Identity API reference](../api/identity/endpoints.md)
- [Gateway routes](https://www.wildbox.io/docs.html#gateway-routes)
- [Security status](../security/status.md)
