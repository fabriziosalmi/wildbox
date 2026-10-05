"""Mock identity service for gateway auth CI tests (#108).

Stdlib-only stand-in for open-security-identity, faithful to the real
/internal/authorize contract (see open-security-identity/app/internal.py):

- 403 {"detail": "Invalid gateway secret"} when X-Gateway-Secret is missing
  or does not match EXPECTED_GATEWAY_SECRET (proof-of-origin, #133/#134);
- 401 for unknown/invalid tokens;
- 200 with {is_authenticated, user_id, team_id, role, permissions, scopes}
  for the fixture tokens below.

Every other path echoes the request back as JSON ({method, path, port,
headers}) so tests can assert exactly which headers the gateway forwarded
upstream (X-Wildbox-* injection, Authorization/X-API-Key stripping), and to
which upstream: ``port`` is the port the request arrived on, one for each
service the mock stands in for (#711).

GET /__mock/counts returns per-token /internal/authorize call counts, which
lets tests prove the gateway's auth cache short-circuits repeat validations.

A dropped connection (#609). For a token starting with ``drop-once-`` the
mock closes the connection without answering the first time it sees it, as
identity does when its keep-alive timeout closes a connection the gateway is
writing into, and authorizes it afterwards. ``drop-always-`` tokens are
dropped every time.

Revocation (#571). Besides the fixture tokens, the mock accepts JWT-shaped
tokens whose (unsigned) payload carries a ``jti``, the way identity's login
tokens do, until POST /__mock/revoke {"jti": ...} blacklists that jti. Like
the real endpoint, the blacklist is consulted *before* the rest of the work:
a payload ``delay_ms`` makes the mock sleep after that check, standing in for
the database query identity runs there, so a test can hold an authorization
in flight across a logout deterministically.

API keys (#593). Fixture keys report the id identity revokes them by
(``api_key_id``); test-minted keys (see dynamic_api_key) also carry an
expiry, reported as ``credential_expires_at``, and are refused after
POST /__mock/revoke {"api_key_id": ...}, the way identity refuses a key it
has marked inactive.

Team memberships (#613). A session whose payload lists ``teams`` (oldest
membership first) is authorized in the first of them its user has not been
removed from, the way identity resolves a session's team; POST
/__mock/remove_member {"user_id": ..., "team_id": ...} commits a removal.
The team is resolved before the ``delay_ms`` pause, so an authorization held
in flight across a removal still answers with the team that was left, as
identity's would when its query ran before the commit.

Scopes (#647). ``wsk_scoped~<key id>~<scopes>`` is a key holding exactly the
comma-separated scopes named (none at all when the list is empty), in a team
of its own, so a test can ask for any scope set without a fixture for each.

Ports. ``MOCK_PORTS`` (comma-separated, default ``8001``) are the ports the
mock listens on. The route-scope tests run the production configuration,
whose upstreams are one service and one port each; the mock answers on all
of them, under the services' names.
"""

import base64
import hmac
import json
import os
import threading
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
        "api_key_id": "key-readonly",
    },
    "wsk_toolsexec_ci_fixture": {
        "user_id": "user-5555",
        "team_id": "team-6666",
        "role": "user",
        "scopes": ["tools:execute"],
        "api_key_id": "key-toolsexec",
    },
    # A sensor's key: telemetry ingest and nothing else (#628).
    "wsk_ingest_ci_fixture": {
        "user_id": "user-7777",
        "team_id": "team-8888",
        "role": "user",
        "scopes": ["data:ingest"],
        "api_key_id": "key-ingest",
    },
    # Keys for what the gateway forwards about a credential (#637): several
    # scopes, in an order that is not alphabetical; a key identity reports
    # no scope list for, which is not limited; a key whose list is empty;
    # and a list holding something that is not a scope name.
    "wsk_multiscope_ci_fixture": {
        "user_id": "user-1212",
        "team_id": "team-1212",
        "role": "member",
        "scopes": ["tools:read", "data:ingest", "data:read"],
        "api_key_id": "key-multiscope",
    },
    "wsk_unlimited_ci_fixture": {
        "user_id": "user-1313",
        "team_id": "team-1313",
        "role": "member",
        "scopes": None,
        "api_key_id": "key-unlimited",
    },
    "wsk_noscopes_ci_fixture": {
        "user_id": "user-1414",
        "team_id": "team-1414",
        "role": "member",
        "scopes": [],
        "api_key_id": "key-noscopes",
    },
    # The session of the scripts that run against the production
    # configuration (upstream_header_tests.sh, cors_tests.sh): a token of
    # its own, so that the authorization counts other scripts assert on do
    # not depend on which script ran first.
    "prod-harness-session-token": {
        "user_id": "user-1616",
        "team_id": "team-1616",
        "role": "admin",
        "scopes": None,
    },
    "wsk_oddscope_ci_fixture": {
        "user_id": "user-1515",
        "team_id": "team-1515",
        "role": "member",
        "scopes": ["tools:read", "not a scope", "data:read\r\nX-Wildbox-Role: owner", "*"],
        "api_key_id": "key-oddscope",
    },
    # An answer for an API key that does not name the key, as identity
    # before #593 gave: the gateway cannot check it against a revocation,
    # so it must not serve it.
    "wsk_unnamed_ci_fixture": {
        "user_id": "user-9999",
        "team_id": "team-9999",
        "role": "user",
        "scopes": ["read"],
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
dropped_tokens = set()
revoked_api_keys = set()
removed_members = set()  # (user_id, team_id)


def dynamic_api_key(token):
    """An API key minted by a test (#593), or None.

    ``wsk_dyn~<key id>~<delay_ms>~<expires_at>``: the key id is what identity
    reports and revokes the key by, ``delay_ms`` holds the authorization in
    flight after the revocation check (as ``delay_ms`` does for sessions), and
    ``expires_at`` (epoch seconds, 0 for none) is when the key expires.
    """
    parts = token.split("~")
    if len(parts) != 4 or parts[0] != "wsk_dyn" or not parts[1]:
        return None
    try:
        return parts[1], int(parts[2]), float(parts[3])
    except ValueError:
        return None


def scoped_api_key(token):
    """A key holding exactly the scopes it names (#647), or None.

    ``wsk_scoped~<key id>~<scope>,<scope>,...``: the key id names the key and
    its team, so two keys never share a rate-limit budget.
    """
    parts = token.split("~")
    if len(parts) != 3 or parts[0] != "wsk_scoped" or not parts[1]:
        return None
    return parts[1], [scope for scope in parts[2].split(",") if scope]


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
        # A service with CORS middleware of its own (#712): the mock answers
        # with the Access-Control-Allow-Origin a test asks it for, so the
        # test can see that the gateway's word replaces it.
        said = self.headers.get("X-Mock-Allow-Origin")
        if said:
            self.send_header("Access-Control-Allow-Origin", said)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Vary", "Accept-Encoding")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
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
                "port": self.server.server_address[1],
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

        if token.startswith("drop-always-") or (
            token.startswith("drop-once-") and token not in dropped_tokens
        ):
            dropped_tokens.add(token)
            self.close_connection = True  # no reply: the gateway reads EOF
            return

        auth = TOKENS.get(token)
        key = dynamic_api_key(token) if auth is None else None
        if key is not None:
            key_id, delay_ms, expires_at = key
            if key_id in revoked_api_keys or (expires_at and expires_at <= time.time()):
                self._reply(401, {"detail": "Invalid or inactive API key"})
                return
            time.sleep(delay_ms / 1000)
            auth = {
                "user_id": "user-" + key_id,
                "team_id": "team-" + key_id,
                "role": "user",
                "scopes": ["*"],
                "api_key_id": key_id,
                "credential_expires_at": expires_at or None,
            }
        scoped = scoped_api_key(token) if auth is None else None
        if scoped is not None:
            key_id, scopes = scoped
            auth = {
                "user_id": "user-" + key_id,
                "team_id": "team-" + key_id,
                "role": "user",
                "scopes": scopes,
                "api_key_id": key_id,
            }
        if auth is None and token.startswith("drop-once-"):
            auth = {
                "user_id": "user-9999",
                "team_id": "team-9999",
                "role": "user",
                "scopes": None,
            }
        claims = jwt_claims(token) if auth is None else None
        if claims is not None:
            if claims["jti"] in revoked_jtis:
                self._reply(401, {"detail": "Token has been revoked"})
                return
            user_id = claims.get("sub", "user-jwt")
            # A team per session unless the session lists its user's teams:
            # the gateway's per-team rate limit must not turn a test's
            # repeated probes into 429s.
            team_id = "team-" + claims["jti"]
            teams = claims.get("teams")
            if isinstance(teams, list):
                remaining = [t for t in teams if (user_id, t) not in removed_members]
                if not remaining:
                    self._reply(401, {"detail": "User not found or inactive"})
                    return
                team_id = remaining[0]
            # Past the blacklist check and the membership query: the real
            # endpoint goes on with its work, and a logout or a removal
            # landing meanwhile goes unnoticed.
            time.sleep(int(claims.get("delay_ms") or 0) / 1000)
            auth = {
                "user_id": user_id,
                "team_id": team_id,
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
                "api_key_id": auth.get("api_key_id"),
                "credential_expires_at": auth.get("credential_expires_at"),
            },
        )

    def _revoke(self):
        length = int(self.headers.get("Content-Length") or 0)
        request = json.loads(self.rfile.read(length) or b"{}")
        if self.path == "/__mock/remove_member":
            removed_members.add((request["user_id"], request["team_id"]))
            self._reply(200, {"removed": [request["user_id"], request["team_id"]]})
            return
        if "api_key_id" in request:
            revoked_api_keys.add(request["api_key_id"])
            self._reply(200, {"revoked": request["api_key_id"]})
            return
        revoked_jtis.add(request["jti"])
        self._reply(200, {"revoked": request["jti"]})

    def do_POST(self):
        if self.path == "/internal/authorize":
            self._authorize()
        elif self.path in ("/__mock/revoke", "/__mock/remove_member"):
            self._revoke()
        else:
            self._echo()

    def do_GET(self):
        if self.path == "/health":
            # Also what a request the gateway maps to a service's /health
            # lands on: say which request it was, as the echo does.
            self._reply(
                200,
                {
                    "status": "ok",
                    "method": self.command,
                    "path": self.path,
                    "port": self.server.server_address[1],
                    "headers": {k.lower(): v for k, v in self.headers.items()},
                },
            )
        elif self.path == "/__mock/counts":
            self._reply(200, dict(authorize_calls))
        else:
            self._echo()

    do_PUT = do_GET
    do_DELETE = do_GET
    do_PATCH = do_POST
    do_HEAD = do_GET

    def log_message(self, fmt, *args):  # keep container logs readable
        print("mock-identity: " + fmt % args, flush=True)


if __name__ == "__main__":
    ports = [int(port) for port in os.environ.get("MOCK_PORTS", "8001").split(",")]
    servers = [ThreadingHTTPServer(("0.0.0.0", port), Handler) for port in ports]
    for server in servers[1:]:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    servers[0].serve_forever()
