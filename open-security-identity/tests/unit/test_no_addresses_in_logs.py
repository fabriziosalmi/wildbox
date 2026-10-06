"""The log names an account by its id, never by what was typed for it (#755).

Three lines carried an email address: the one about a locked account, with
the address as it was typed into the login form (which is whatever was
typed there, a password pasted into the wrong field included), and the two
about a registration. And the database engine, with ``DEBUG`` on, logged
every statement with its parameters, as did the text of any database error
the service logs: addresses, password hashes, the hashes of API keys.
"""

import asyncio
import hashlib
import logging
import os
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost:5432/test")
os.environ.setdefault("JWT_SECRET_KEY", "a" * 32)

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app import database, token_blacklist, user_manager  # noqa: E402
from app.config import settings  # noqa: E402
from starlette.requests import Request  # noqa: E402

TYPED = "Hunter2-typed-in-the-wrong-field-" + uuid.uuid4().hex
ADDRESS = f"new-{uuid.uuid4().hex}@example.com"


class Attempts:
    """The three Redis commands the lockout uses."""

    def __init__(self, count):
        self.count = count
        self.kept = {}

    async def exists(self, key):
        return key in self.kept

    async def get(self, key):
        return str(self.count)

    async def setex(self, key, seconds, value):
        self.kept[key] = (seconds, value)


def test_a_lockout_is_logged_with_a_digest_of_the_address(monkeypatch, caplog):
    redis = Attempts(settings.max_failed_login_attempts)

    async def get_redis():
        return redis

    monkeypatch.setattr(token_blacklist, "get_redis", get_redis)

    with caplog.at_level(logging.DEBUG):
        locked = asyncio.run(token_blacklist.is_account_locked(TYPED))

    assert locked is True
    assert redis.kept, "the lockout is still recorded"
    assert TYPED not in caplog.text
    assert TYPED.lower() not in caplog.text.lower()
    (record,) = [r for r in caplog.records if "Account locked" in r.getMessage()]
    assert record.getMessage() == (
        f"Account locked after {settings.max_failed_login_attempts} failed attempts "
        f"(account {token_blacklist.account_digest(TYPED)})"
    )


def test_the_digest_can_be_computed_for_an_address_one_knows():
    # printf %s alice@example.com | shasum -a 256
    known = hashlib.sha256(b"alice@example.com").hexdigest()[:12]

    assert token_blacklist.account_digest("alice@example.com") == known
    # As the address is compared at login: case and surrounding space apart.
    assert token_blacklist.account_digest("  Alice@Example.COM ") == known
    assert token_blacklist.account_digest("bob@example.com") != known
    assert len(known) == 12


class RegistrationSession:
    def __init__(self):
        self.added = []

    def add(self, row):
        self.added.append(row)

    async def flush(self):
        for row in self.added:
            if getattr(row, "id", None) is None:
                row.id = uuid.uuid4()

    async def commit(self):
        pass


def test_a_registration_is_logged_by_the_users_id(caplog):
    session = RegistrationSession()
    manager = user_manager.UserManager(SimpleNamespace(session=session))
    user = SimpleNamespace(id=uuid.uuid4(), email=ADDRESS)
    request = Request({"type": "http", "method": "POST", "path": "/", "headers": []})

    with caplog.at_level(logging.DEBUG, logger="app.user_manager"):
        asyncio.run(manager.on_after_register(user, request))

    assert [type(row).__name__ for row in session.added] == ["Team", "TeamMembership"]
    lines = [r.getMessage() for r in caplog.records if r.name == "app.user_manager"]
    assert lines, "the registration is still logged"
    assert ADDRESS not in "\n".join(lines)
    assert sum(str(user.id) in line for line in lines) == 2


def test_the_engine_hides_the_parameters_of_its_statements():
    """Neither DEBUG's echo nor the text of a database error has the values."""
    assert database.engine.sync_engine.hide_parameters is True


def test_what_a_database_error_says_with_parameters_hidden():
    """The behaviour the setting buys, on an engine a unit test can open."""
    from sqlalchemy import create_engine, text
    from sqlalchemy.exc import SQLAlchemyError

    def failing(hide):
        engine = create_engine("sqlite://", hide_parameters=hide)
        try:
            with engine.connect() as connection:
                connection.execute(
                    text("SELECT * FROM no_such_table WHERE email = :email"),
                    {"email": ADDRESS},
                )
        except SQLAlchemyError as error:
            return str(error)
        finally:
            engine.dispose()
        raise AssertionError("the statement was expected to fail")

    assert ADDRESS in failing(False)
    hidden = failing(True)
    assert ADDRESS not in hidden
    assert "no_such_table" in hidden
