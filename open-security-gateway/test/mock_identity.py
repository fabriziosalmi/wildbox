"""Mock identity service for gateway auth CI tests (#108).

Stdlib-only stand-in for open-security-identity, faithful to the real
/internal/authorize contract (see open-security-identity/app/internal.py):

- 403 {"detail": "Invalid gateway secret"} when X-Gateway-Secret is missing
  or does not match EXPECTED_GATEWAY_SECRET (proof-of-origin, #133/#134);
- 401 for unknown/invalid tokens;
- 200 with {is_authenticated, user_id, team_id, role, permissions, scopes}
  for the fixture tokens below.

Every other path echoes the request back as JSON ({method, path, headers})
so tests can assert exactly which headers the gateway forwarded upstream
(X-Wildbox-* injection, Authorization/X-API-Key stripping).

GET /__mock/counts returns per-token /internal/authorize call counts, which
lets tests prove the gateway's auth cache short-circuits repeat validations.

Revocation (#571). Besides the fixture tokens, the mock accepts JWT-shaped
tokens whose (unsigned) payload carries a ``jti``, the way identity's login
tokens do, until POST /__mock/revoke {"jti": ...} blacklists that jti. Like
the real endpoint, the blacklist is consulted *before* the rest of the work:
a payload ``delay_ms`` makes the mock sleep after that check, standing in for
the database query identity runs there, so a test can hold an authorization
in flight across a logout deterministically.
"""

import base64
import hmac
import json
import os
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

EXPECTED_SECRET = os.environ.get("EXPECTED_GATEWAY_SECRET", "")

# token -> auth payload returned to the gateway. scopes=None means
# unrestricted (interactive/JWT or legacy key), a list is enforced by
# auth_handler.enforce_scopes at the gateway.
TOKENS = {
    "valid-bearer-token": {
        "user_id": "user-1111",
        "team_id": "team-2222",
        "role": "admin",
        "scopes": None,
    },
    "wsk_readonly_ci_fixture": {
        "user_id": "user-3333",
        "team_id": "team-4444",
        "role": "user",
        "scopes": ["read"],
    },
    "wsk_toolsexec_ci_fixture": {
        "user_id": "user-5555",
        "team_id": "team-6666",
        "role": "user",
        "scopes": ["tools:execute"],
    },
    # An account a team admin created, before it changed the initial
    # password (#573): identity reports password_change_required.
    "pending-password-change-token": {
        "user_id": "user-7777",
        "team_id": "team-8888",
        "role": "member",
        "scopes": None,
        "password_change_required": True,
    },
}

authorize_calls = Counter()
revoked_jtis = set()


def jwt_claims(token):
    """The payload of a JWT-shaped token, or None. Unsigned: test fixture."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded))
    except ValueError:
        return None
    return claims if isinstance(claims, dict) and claims.get("jti") else None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _reply(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _echo(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)  # drain body to keep the connection clean
        self._reply(
            200,
            {
                "method": self.command,
                "path": self.path,
                "headers": {k.lower(): v for k, v in self.headers.items()},
            },
        )

    def _authorize(self):
        # Always drain the request body BEFORE replying: on a keep-alive
        # connection, unread body bytes would be misparsed as the next
        # request line after an early 403.
        length = int(self.headers.get("Content-Length") or 0)
        raw_body = self.rfile.read(length) if length else b""

        secret = self.headers.get("X-Gateway-Secret") or ""
        if not EXPECTED_SECRET or not hmac.compare_digest(secret, EXPECTED_SECRET):
            self._reply(403, {"detail": "Invalid gateway secret"})
            return

        try:
            request = json.loads(raw_body or b"{}")
        except ValueError:
            self._reply(400, {"detail": "Malformed authorize request"})
            return

        token = request.get("token", "")
        authorize_calls[token] += 1

        auth = TOKENS.get(token)
        claims = jwt_claims(token) if auth is None else None
        if claims is not None:
            if claims["jti"] in revoked_jtis:
                self._reply(401, {"detail": "Token has been revoked"})
                return
            # Past the blacklist check: the real endpoint now queries the
            # database, and a logout landing meanwhile goes unnoticed.
            time.sleep(int(claims.get("delay_ms") or 0) / 1000)
            auth = {
                "user_id": claims.get("sub", "user-jwt"),
                # A team per session: the gateway's per-team rate limit must
                # not turn a test's repeated probes into 429s.
                "team_id": "team-" + claims["jti"],
                "role": "user",
                "scopes": None,
            }
        if auth is None:
            self._reply(401, {"detail": "Invalid or inactive credentials"})
            return

        self._reply(
            200,
            {
                "is_authenticated": True,
                "user_id": auth["user_id"],
                "team_id": auth["team_id"],
                "role": auth["role"],
                "permissions": ["tool:basic", "tool:advanced", "feed", "cspm"],
                "scopes": auth["scopes"],
                "password_change_required": auth.get("password_change_required", False),
            },
        )

    def _revoke(self):
        length = int(self.headers.get("Content-Length") or 0)
        request = json.loads(self.rfile.read(length) or b"{}")
        revoked_jtis.add(request["jti"])
        self._reply(200, {"revoked": request["jti"]})

    def do_POST(self):
        if self.path == "/internal/authorize":
            self._authorize()
        elif self.path == "/__mock/revoke":
            self._revoke()
        else:
            self._echo()

    def do_GET(self):
        if self.path == "/health":
            self._reply(200, {"status": "ok"})
        elif self.path == "/__mock/counts":
            self._reply(200, dict(authorize_calls))
        else:
            self._echo()

    do_PUT = do_GET
    do_DELETE = do_GET

    def log_message(self, fmt, *args):  # keep container logs readable
        print("mock-identity: " + fmt % args, flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8001), Handler).serve_forever()
