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

1. identity tells the gateway to refuse the token's `jti`, on the gateway's
   internal listener (port 8081, reachable only on the Compose network, not
   published to the host). The gateway records a revocation marker shared
   by all its workers and checks it on every request, whether or not it has
   a cached decision for the token, so a request that was being authorized
   while the logout ran is refused too;
2. identity writes the `jti` to a blacklist in Redis, kept until the token
   would have expired anyway, which identity's own routes and its
   authorization endpoint refuse from then on.

Logout answers success only once both are done. If the gateway does not
confirm (identity tries three times) or Redis cannot be written, it answers
503 and the token stays valid; repeating the logout is safe.

Limits to know:

- Logout revokes **one token**, the one presented. There is no "log out
  everywhere", and changing a password does not revoke tokens issued before
  the change; they expire on their own within 30 minutes.
- Tokens issued before the upgrade that added the `jti` claim carry none.
  Logging out with one answers 400 ("Token carries no jti and cannot be
  revoked individually"); it expires within 30 minutes of being issued.
- The blacklist lives in Redis and is checked **fail-open**: if identity
  cannot reach Redis, it logs the error and treats tokens as not revoked.
  Traffic through the gateway is still refused by its marker, which lasts
  for the token's remaining lifetime unless the gateway restarts.
- The marker is kept by the gateway instance identity reaches. With more
  than one gateway replica, the others refuse the token only once their
  cached decision expires (`AUTH_CACHE_TTL`, 300 seconds by default).

Deactivating a user (`PATCH /api/v1/identity/admin/users/{user_id}/status`)
also clears the gateway's authorization cache, and the gateway refuses
inactive users' tokens and API keys from then on.

### A Password Change Ends the Other Sessions

Changing a password ends every session of the account issued up to that
moment, so changing it after a compromise locks the intruder out:

- identity stores the time of the change (`users.tokens_valid_after`) and
  refuses a session token whose `iat` is not later, on its own routes and
  when the gateway asks. A token without an `iat` is refused too.
- Before it changes the password, identity sends the same cutoff to the
  gateway, which keeps it per user and checks it on every request, cached
  decision or not. If the gateway does not confirm, the password is not
  changed and the request answers 503; try again.
- The session that made the change is ended as well, and
  `change-password` answers with a new access token for it. Login tokens
  carry a fractional `iat`, so the new token is told apart from the ones
  it replaces even within the same second.
- API keys are not sessions and keep working. Revoke them on the API keys
  page if they may be compromised.

This applies to `change-password`, to the reset-password flow and to an
administrator's reset through `PATCH /auth/users/{id}`. As with logout,
other gateway replicas than the one identity reaches refuse those sessions
only once their cached decisions expire.

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

A wrong current password counts towards the same lock: on change-password,
on account deletion and on an email change (below). A locked account is
refused there with the same 429, so a session cannot be used to guess the
password either.

Like the blacklist, the lockout check is fail-open: while Redis is unreachable,
logins are not counted or refused.

---

## Passwords

Passwords are hashed with Argon2id through fastapi-users' `PasswordHelper`.
Hashes written by older releases with bcrypt still verify.

A user changes their own password with
`POST /api/v1/identity/admin/me/change-password` (or
`PUT /api/v1/identity/admin/me/password`), with `current_password` and
`new_password` (at least 12 characters). It checks the current password
first, ends the account's other sessions and answers with a new access
token for this one. `PATCH /auth/users/me` and
`PATCH /api/v1/identity/admin/me/profile` refuse a password, and so does
`PATCH /auth/users/{id}` when the id is the caller's own.

Changing the email address (`PATCH /auth/users/me` or
`PATCH /api/v1/identity/admin/me/profile`) requires `current_password` as
well, and so does deleting one's own account
(`DELETE /api/v1/identity/admin/me/account`). A password-reset token stops
working once the account's email changes. The full list of routes is in the
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
