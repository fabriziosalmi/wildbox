"""identity's /health reports its database and its Redis from real checks (#559).

The admin page showed Database and Redis as healthy whenever identity
answered at all; it now reads them from these checks. The database session
and the Redis client are replaced with stubs, so this needs neither.
"""

import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost:5432/test")
os.environ.setdefault("JWT_SECRET_KEY", "a" * 32)

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import app.database as database  # noqa: E402
import app.main as main  # noqa: E402
import app.token_blacklist as token_blacklist  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from redis.exceptions import ConnectionError as RedisConnectionError  # noqa: E402
from sqlalchemy.exc import OperationalError  # noqa: E402


class _Session:
    def __init__(self, fail: bool):
        self.fail = fail

    async def execute(self, _statement):
        if self.fail:
            raise OperationalError("SELECT 1", {}, Exception("connection refused"))

    async def close(self):
        pass


class _Redis:
    def __init__(self, fail: bool):
        self.fail = fail

    async def ping(self):
        if self.fail:
            raise RedisConnectionError("connection refused")
        return True


@pytest.fixture
def stack(monkeypatch):
    state = {"db_down": False, "redis_down": False}

    async def get_db():
        yield _Session(state["db_down"])

    async def get_redis():
        return _Redis(state["redis_down"])

    # The request middleware opens a session through main's own reference;
    # the handler imports it from app.database at call time.
    monkeypatch.setattr(main, "get_db", get_db)
    monkeypatch.setattr(database, "get_db", get_db)
    monkeypatch.setattr(token_blacklist, "get_redis", get_redis)
    return state


def _health():
    response = TestClient(main.app).get("/health")
    assert response.status_code == 200
    return response.json()


def test_everything_up(stack):
    body = _health()
    assert body["status"] == "healthy"
    assert body["checks"]["database"]["status"] == "healthy"
    assert body["checks"]["redis"]["status"] == "healthy"


def test_redis_down_degrades_the_service(stack):
    stack["redis_down"] = True
    body = _health()
    assert body["status"] == "degraded"
    assert body["checks"]["database"]["status"] == "healthy"
    assert body["checks"]["redis"] == {"status": "unhealthy"}


def test_database_down_is_unhealthy_whatever_redis_says(stack):
    stack["db_down"] = True
    body = _health()
    assert body["status"] == "unhealthy"
    assert body["checks"]["database"] == {"status": "unhealthy"}
    assert body["checks"]["redis"]["status"] == "healthy"


def test_the_report_carries_no_connection_details(stack):
    """The gateway exposes this to signed-in users: statuses only."""
    stack["redis_down"] = True
    body = _health()
    text = str(body).lower()
    for detail in ("redis://", "postgresql", "password", "refused"):
        assert detail not in text
