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

Deactivating or deleting an account ends its sessions and its API keys at
once; see [Revoking an API key](#revoking-an-api-key).

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

### Revoking an API Key

`DELETE /api/v1/identity/api-keys/{key_prefix}` revokes one of the caller's
keys; a team owner or admin revokes a team's key with
`DELETE /api/v1/identity/teams/{team_id}/api-keys/{key_prefix}`. The key is
refused on the next request, although the gateway caches the decision
for a key:

- before it marks the key inactive, identity tells the gateway to refuse
  it, by the key's id (identity does not keep the key itself, and reports
  the id with every authorization it grants for the key). The gateway
  records a marker shared by all its workers and checks it on every
  request, cached decision or not, so a request that was being authorized
  while the key was revoked is refused too;
- if the gateway does not confirm, the key is not revoked and the request
  answers 503; try again.

Every other change that disables a key does the same, with the same 503
when the gateway does not confirm:

| Change | Keys refused at once |
| --- | --- |
| An administrator deactivates the account (`PATCH /api/v1/identity/admin/users/{user_id}/status`, or `PATCH /auth/users/{id}` with `is_active: false`) | All the account's keys, and every session of the account |
| An administrator deletes the account (`DELETE /api/v1/identity/admin/users/{user_id}` or `DELETE /auth/users/{id}`) | All the account's keys, the keys of the teams deleted with it, and every session |
| A user deletes their own account (`DELETE /api/v1/identity/admin/me/account`) | All the account's keys, and every session, the current one included |
| A team owner or admin, or a superuser, removes a member (`DELETE /api/v1/identity/admin/teams/{team_id}/members/{user_id}`) | The member's keys for that team, and their sessions in that team; see [Removing a member from a team](#removing-a-member-from-a-team) |

A key with an expiry (`expires_at` when it is created) is refused from that
moment: identity reports the expiry with every authorization, and the
gateway does not serve a cached decision past it.

A password change does not revoke API keys: they are not sessions. Revoke a
key that may be compromised on its own. As with logout, the marker is kept by
the gateway instance identity reaches; other replicas refuse the key once
their cached decision expires.

### Removing a Member from a Team

A session is not bound to a team: on every request the gateway does not
answer from its cache, identity resolves the session's team as the user's
oldest membership, and the gateway caches that decision. Removing a member
ends their sessions in that team on the next request, and only there:

- before it deletes the membership, identity sends the gateway the user, the
  team and the time of the removal, after the member's API keys for the
  team. The gateway records a marker shared by all its workers and refuses
  a session decision of that user in that team whose token was issued up to
  the removal, cached decision or not, so a request that was being
  authorized during the removal is refused too;
- if the gateway does not confirm, the member is not removed and the request
  answers 503; try again;
- the refused request answers 403 `team_membership_ended`, not 401: the
  session is still valid. The gateway drops the cached decision, so the next
  request with the same session is authorized afresh and works in the
  oldest team the user still belongs to. A user with no team left gets 401;
- a session issued before the removal does not work in that team again,
  even if the user is added back, until it expires; a new login does.

A team is deleted only with the account that is its sole member, and
deleting an account ends all its sessions. Members cannot remove
themselves. As with logout, other gateway replicas than the one identity
reaches refuse the session in the team only once their cached decisions
expire.

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

### Password Policy

Every new password goes through one rule, in identity's
`UserManager.validate_password()` (`app/password_policy.py`). It follows
NIST SP 800-63B: length and a list of passwords actually in use, no
composition rules. A password is refused when it:

- is shorter than 12 or longer than 128 characters;
- contains the account's email address, or the part before the `@` when
  that part has at least 4 characters (case does not matter);
- is one of the 10,000 most common passwords of 12 characters or more
  (case does not matter). The list is vendored in identity
  (`app/data/common_passwords.txt`, from SecLists, MIT license); it is
  never fetched over the network.

There is no requirement for an uppercase letter, a digit or a symbol:
such rules push people towards predictable patterns without making
passwords harder to guess. The maximum bounds the work a single request
can cause (Argon2 digests the whole input on every hash); 128 characters
is well beyond any passphrase or password manager.

The rule applies wherever a password is set: registration, the
reset-password flow, change-password, an administrator's reset of another
account (`PATCH /auth/users/{id}`), the accounts a team owner or admin
creates (`POST /api/v1/identity/admin/teams/{team_id}/members`) and the
first administrator created from `INITIAL_ADMIN_PASSWORD`, whose creation
stops identity's start with the reason if the password does not comply.
A refused password answers
400 with the reason as the error message (registration:
`REGISTER_INVALID_PASSWORD`, reset: `RESET_PASSWORD_INVALID_PASSWORD`,
administrator's reset: `UPDATE_USER_INVALID_PASSWORD`, in
`error.details.code`). Existing passwords are not checked; an account
meets the rule the next time its password is set.

A user changes their own password with
`POST /api/v1/identity/admin/me/change-password` (or
`PUT /api/v1/identity/admin/me/password`), with `current_password` and
`new_password` (subject to the policy above). It checks the current password
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
