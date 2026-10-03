"""Identity's business counts are for platform superusers only (#664).

GET /api/v1/admin/metrics accepted the X-Gateway-Secret header alone. The
gateway passes every request under /api/v1/identity/ through to identity
without authenticating it, and stamped that header on all of them, so an
anonymous GET /api/v1/identity/admin/metrics read the number of users, teams
and active API keys. The route now authenticates the caller from the bearer
token and requires is_superuser; the header counts for nothing there.

The tokens are real JWTs from identity's own strategy, read back by the real
fastapi-users dependencies; only the user store and the database session are
stubs, so no service is needed.
"""

import ast
import asyncio
import inspect
import os
import sys
import textwrap
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost:5432/test")
os.environ.setdefault("JWT_SECRET_KEY", "a" * 32)

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import app.database as database  # noqa: E402
import app.main as main  # noqa: E402
from app import user_manager  # noqa: E402
from app.config import settings  # noqa: E402
from fastapi.routing import APIRoute  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

SECRET = "unit-test-gateway-proof-of-origin"
METRICS = "/api/v1/admin/metrics"


def make_user(**fields):
    user = SimpleNamespace(
        id=uuid.uuid4(),
        email="alice@example.com",
        is_active=True,
        is_superuser=False,
        is_verified=True,
        must_change_password=False,
        tokens_valid_after=None,
    )
    for name, value in fields.items():
        setattr(user, name, value)
    return user


class UserStore:
    """What fastapi-users reads to resolve a token's subject."""

    def __init__(self, *users):
        self.users = {user.id: user for user in users}

    async def get(self, user_id):
        return self.users.get(user_id)


class Counts:
    """A session that answers every count query with 7."""

    async def execute(self, _query):
        return SimpleNamespace(scalar=lambda: 7)

    async def close(self):
        pass


@pytest.fixture
def client(monkeypatch):
    member = make_user()
    admin = make_user(email="root@example.com", is_superuser=True)
    flagged = make_user(
        email="new@example.com", is_superuser=True, must_change_password=True
    )
    store = UserStore(member, admin, flagged)

    async def the_manager():
        yield user_manager.UserManager(store)

    async def get_db():
        yield Counts()

    async def not_blacklisted(_jti):
        return False

    monkeypatch.setattr(settings, "gateway_internal_secret", SECRET)
    monkeypatch.setattr(user_manager, "is_token_blacklisted", not_blacklisted)
    monkeypatch.setattr(main, "get_db", get_db)
    monkeypatch.setattr(database, "get_db", get_db)
    app = main.app
    app.dependency_overrides[user_manager.get_user_manager] = the_manager

    async def token(user):
        return await user_manager.get_jwt_strategy().write_token(user)

    tokens = {
        name: asyncio.run(token(user))
        for name, user in (("member", member), ("admin", admin), ("flagged", flagged))
    }
    yield TestClient(app), tokens
    app.dependency_overrides.clear()


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def test_an_anonymous_caller_is_refused(client):
    http, _ = client
    assert http.get(METRICS).status_code == 401


def test_the_gateway_secret_alone_is_refused(client):
    """The header the gateway stamped on every passthrough request."""
    http, _ = client
    response = http.get(METRICS, headers={"X-Gateway-Secret": SECRET})
    assert response.status_code == 401
    assert "users_total" not in response.text


def test_a_team_owner_who_is_not_a_superuser_is_refused(client):
    """Every registered account owns its personal team: that is no platform role."""
    http, tokens = client
    response = http.get(
        METRICS, headers={**bearer(tokens["member"]), "X-Gateway-Secret": SECRET}
    )
    assert response.status_code == 403
    assert "users_total" not in response.text


def test_a_superuser_reads_the_counts(client):
    http, tokens = client
    response = http.get(METRICS, headers=bearer(tokens["admin"]))
    assert response.status_code == 200
    counts = response.json()["metrics"]
    assert counts == {"users_total": 7, "teams_total": 7, "api_keys_active": 7}


def test_a_superuser_who_must_change_the_password_is_refused(client):
    http, tokens = client
    response = http.get(METRICS, headers=bearer(tokens["flagged"]))
    assert response.status_code == 403


# -- which routes trust the gateway secret ------------------------------------


def _code(function):
    """The function's source without docstrings or comments."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(function)))
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if (
            isinstance(body, list)
            and body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            body.pop(0)
    return ast.unparse(tree)


def _routes(routes):
    """Every endpoint route, with its full path.

    FastAPI 0.141 keeps an included router as one entry that expands into
    its routes on demand; older versions copied the routes into the app.
    """
    for route in routes:
        expand = getattr(route, "effective_candidates", None)
        if callable(expand):
            yield from _routes(expand())
        elif isinstance(route, APIRoute) or (
            getattr(route, "endpoint", None) and getattr(route, "path", None)
        ):
            yield route


def _reads_the_gateway_secret(route):
    code = _code(route.endpoint).lower()
    return "gateway_internal_secret" in code or "x-gateway-secret" in code


def test_the_audit_sees_a_route_that_reads_the_header():
    async def endpoint(request):
        """Mentions X-Gateway-Secret in prose only."""
        return request.headers.get("X-Gateway-Secret")

    async def prose_only():
        """Mentions X-Gateway-Secret in prose only."""
        return None

    assert _reads_the_gateway_secret(SimpleNamespace(endpoint=endpoint))
    assert not _reads_the_gateway_secret(SimpleNamespace(endpoint=prose_only))


def test_only_internal_routes_trust_the_gateway_secret():
    """The secret proves a request came from the gateway, not who sent it.

    The gateway forwards it to the routes it authenticated and calls the
    /internal routes with it itself; no other identity route may treat it
    as a credential.
    """
    routes = list(_routes(main.app.routes))
    assert METRICS in {route.path for route in routes}
    trusting = sorted(
        route.path for route in routes if _reads_the_gateway_secret(route)
    )
    assert f"{settings.internal_api_prefix}/authorize" in trusting
    assert all(
        path.startswith(f"{settings.internal_api_prefix}/") for path in trusting
    ), trusting
